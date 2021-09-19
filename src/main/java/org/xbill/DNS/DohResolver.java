// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import lombok.SneakyThrows;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.AsyncSemaphore.Permit;
import org.xbill.DNS.utils.base64;

/**
 * Proof-of-concept <a href="https://tools.ietf.org/html/rfc8484">DNS over HTTP (DoH)</a> resolver.
 * This class is not suitable for high load scenarios because of the shortcomings of Java's built-in
 * HTTP clients. For more control, implement your own {@link Resolver} using e.g. <a
 * href="https://github.com/square/okhttp/">OkHttp</a>.
 *
 * <p>On Java 8, it uses HTTP/1.1, which is against the recommendation of RFC 8484 to use HTTP/2 and
 * thus slower. On Java 11 or newer, HTTP/2 is always used, but the built-in HttpClient has its own
 * <a href="https://bugs.openjdk.java.net/browse/JDK-8225647">issues</a> with connection handling.
 *
 * <p>As of 2020-09-13, the following limits of public resolvers for HTTP/2 were observed:
 * <li>https://cloudflare-dns.com/dns-query: max streams=250, idle timeout=400s
 * <li>https://dns.google/dns-query: max streams=100, idle timeout=240s
 *
 * @since 3.0
 */
@Slf4j
public final class DohResolver implements Resolver {
  private static final boolean USE_HTTP_CLIENT;
  private static final Map<Executor, Object> httpClients =
      Collections.synchronizedMap(new WeakHashMap<>());
  private final SSLSocketFactory sslSocketFactory;

  private static Object defaultHttpRequestBuilder;
  private static Method publisherOfByteArrayMethod;
  private static Method requestBuilderTimeoutMethod;
  private static Method requestBuilderCopyMethod;
  private static Method requestBuilderUriMethod;
  private static Method requestBuilderBuildMethod;
  private static Method requestBuilderPostMethod;

  private static Method httpClientNewBuilderMethod;
  private static Method httpClientBuilderTimeoutMethod;
  private static Method httpClientBuilderExecutorMethod;
  private static Method httpClientBuilderBuildMethod;
  private static Method httpClientSendAsyncMethod;

  private static Method byteArrayBodyPublisherMethod;
  private static Method httpResponseBodyMethod;
  private static Method httpResponseStatusCodeMethod;

  private boolean usePost = false;
  private Duration timeout = Duration.ofSeconds(5);
  private String uriTemplate;
  private final Duration idleConnectionTimeout;
  private OPTRecord queryOPT = new OPTRecord(0, 0, 0);
  private TSIG tsig;
  private Executor defaultExecutor = ForkJoinPool.commonPool();

  /**
   * Maximum concurrent HTTP/2 streams or HTTP/1.1 connections.
   *
   * <p>rfc7540#section-6.5.2 recommends a minimum of 100 streams for HTTP/2.
   */
  private final AsyncSemaphore maxConcurrentRequests;

  private final AtomicLong lastRequest = new AtomicLong(0);
  private final AsyncSemaphore initialRequestLock = new AsyncSemaphore(1);

  private static final String APPLICATION_DNS_MESSAGE = "application/dns-message";

  static {
    boolean initSuccess = false;
    if (!System.getProperty("java.version").startsWith("1.")) {
      try {
        Class<?> httpClientBuilderClass = Class.forName("java.net.http.HttpClient$Builder");
        Class<?> httpClientClass = Class.forName("java.net.http.HttpClient");
        Class<?> httpVersionEnum = Class.forName("java.net.http.HttpClient$Version");
        Class<?> httpRequestBuilderClass = Class.forName("java.net.http.HttpRequest$Builder");
        Class<?> httpRequestClass = Class.forName("java.net.http.HttpRequest");
        Class<?> bodyPublishersClass = Class.forName("java.net.http.HttpRequest$BodyPublishers");
        Class<?> bodyPublisherClass = Class.forName("java.net.http.HttpRequest$BodyPublisher");
        Class<?> httpResponseClass = Class.forName("java.net.http.HttpResponse");
        Class<?> bodyHandlersClass = Class.forName("java.net.http.HttpResponse$BodyHandlers");
        Class<?> bodyHandlerClass = Class.forName("java.net.http.HttpResponse$BodyHandler");

        // HttpClient.Builder
        httpClientBuilderTimeoutMethod =
            httpClientBuilderClass.getDeclaredMethod("connectTimeout", Duration.class);
        httpClientBuilderExecutorMethod =
            httpClientBuilderClass.getDeclaredMethod("executor", Executor.class);
        httpClientBuilderBuildMethod = httpClientBuilderClass.getDeclaredMethod("build");

        // HttpClient
        httpClientNewBuilderMethod = httpClientClass.getDeclaredMethod("newBuilder");
        httpClientSendAsyncMethod =
            httpClientClass.getDeclaredMethod("sendAsync", httpRequestClass, bodyHandlerClass);

        // HttpRequestBuilder
        Method requestBuilderHeaderMethod =
            httpRequestBuilderClass.getDeclaredMethod("header", String.class, String.class);
        Method requestBuilderVersionMethod =
            httpRequestBuilderClass.getDeclaredMethod("version", httpVersionEnum);
        requestBuilderTimeoutMethod =
            httpRequestBuilderClass.getDeclaredMethod("timeout", Duration.class);
        requestBuilderUriMethod = httpRequestBuilderClass.getDeclaredMethod("uri", URI.class);
        requestBuilderCopyMethod = httpRequestBuilderClass.getDeclaredMethod("copy");
        requestBuilderBuildMethod = httpRequestBuilderClass.getDeclaredMethod("build");
        requestBuilderPostMethod =
            httpRequestBuilderClass.getDeclaredMethod("POST", bodyPublisherClass);

        // HttpRequest
        Method requestBuilderNewBuilderMethod = httpRequestClass.getDeclaredMethod("newBuilder");

        // BodyPublishers
        publisherOfByteArrayMethod =
            bodyPublishersClass.getDeclaredMethod("ofByteArray", byte[].class);

        // BodyPublisher
        byteArrayBodyPublisherMethod = bodyHandlersClass.getDeclaredMethod("ofByteArray");

        // HttpResponse
        httpResponseBodyMethod = httpResponseClass.getDeclaredMethod("body");
        httpResponseStatusCodeMethod = httpResponseClass.getDeclaredMethod("statusCode");

        // defaultHttpRequestBuilder = HttpRequest.newBuilder();
        // defaultHttpRequestBuilder.version(HttpClient.Version.HTTP_2);
        // defaultHttpRequestBuilder.header("Content-Type", "application/dns-message");
        // defaultHttpRequestBuilder.header("Accept", "application/dns-message");
        defaultHttpRequestBuilder = requestBuilderNewBuilderMethod.invoke(null);
        @SuppressWarnings({"unchecked", "rawtypes"})
        Enum<?> http2Version = Enum.valueOf((Class<Enum>) httpVersionEnum, "HTTP_2");
        requestBuilderVersionMethod.invoke(defaultHttpRequestBuilder, http2Version);
        requestBuilderHeaderMethod.invoke(
            defaultHttpRequestBuilder, "Content-Type", APPLICATION_DNS_MESSAGE);
        requestBuilderHeaderMethod.invoke(
            defaultHttpRequestBuilder, "Accept", APPLICATION_DNS_MESSAGE);
        initSuccess = true;
      } catch (ClassNotFoundException
          | NoSuchMethodException
          | IllegalAccessException
          | InvocationTargetException e) {
        // fallback to Java 8
        log.warn("Java >= 11 detected, but HttpRequest not available");
      }
    }

    USE_HTTP_CLIENT = initSuccess;
  }

  /**
   * Creates a new DoH resolver that performs lookups with HTTP GET and the default timeout (5s).
   *
   * @param uriTemplate the URI to use for resolving, e.g. {@code https://dns.google/dns-query}
   */
  public DohResolver(String uriTemplate) {
    this(uriTemplate, 100, Duration.ofMinutes(2));
  }

  /**
   * Creates a new DoH resolver that performs lookups with HTTP GET and the default timeout (5s).
   *
   * @param uriTemplate the URI to use for resolving, e.g. {@code https://dns.google/dns-query}
   * @param maxConcurrentRequests Maximum concurrent HTTP/2 streams for Java 11+ or HTTP/1.1
   *     connections for Java 8. On Java 8 this cannot exceed the system property {@code
   *     http.maxConnections}.
   * @param idleConnectionTimeout Max. idle time for HTTP/2 connections until a request is
   *     serialized. Applies to Java 11+ only.
   * @since 3.3
   */
  public DohResolver(
      String uriTemplate, int maxConcurrentRequests, Duration idleConnectionTimeout) {
    this.uriTemplate = uriTemplate;
    this.idleConnectionTimeout = idleConnectionTimeout;
    if (maxConcurrentRequests <= 0) {
      throw new IllegalArgumentException("maxConcurrentRequests must be > 0");
    }
    if (!USE_HTTP_CLIENT) {
      try {
        int javaMaxConn = Integer.parseInt(System.getProperty("http.maxConnections", "5"));
        if (maxConcurrentRequests > javaMaxConn) {
          maxConcurrentRequests = javaMaxConn;
        }
      } catch (NumberFormatException nfe) {
        // well, use what we got
      }
    }
    this.maxConcurrentRequests = new AsyncSemaphore(maxConcurrentRequests);
    try {
      sslSocketFactory = SSLContext.getDefault().getSocketFactory();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @SneakyThrows
  private Object getHttpClient(Executor executor) {
    return httpClients.computeIfAbsent(
        executor,
        key -> {
          try {
            // return HttpClient.newBuilder()
            //   .connectTimeout(timeout).
            //   .executor(executor)
            //   .build();
            Object httpClientBuilder = httpClientNewBuilderMethod.invoke(null);
            httpClientBuilderTimeoutMethod.invoke(httpClientBuilder, timeout);
            httpClientBuilderExecutorMethod.invoke(httpClientBuilder, key);
            return httpClientBuilderBuildMethod.invoke(httpClientBuilder);
          } catch (IllegalAccessException | InvocationTargetException e) {
            log.warn("Could not create a HttpClient with for Executor {}", key, e);
            return null;
          }
        });
  }

  /** Not implemented. Specify the port in {@link #setUriTemplate(String)} if required. */
  @Override
  public void setPort(int port) {
    // Not implemented, port is part of the URI
  }

  /** Not implemented. */
  @Override
  public void setTCP(boolean flag) {
    // Not implemented, HTTP is always TCP
  }

  /** Not implemented. */
  @Override
  public void setIgnoreTruncation(boolean flag) {
    // Not implemented, protocol uses TCP and doesn't have truncation
  }

  /**
   * Sets the EDNS information on outgoing messages.
   *
   * @param version The EDNS version to use. 0 indicates EDNS0 and -1 indicates no EDNS.
   * @param payloadSize ignored
   * @param flags EDNS extended flags to be set in the OPT record.
   * @param options EDNS options to be set in the OPT record
   */
  @Override
  public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
    switch (version) {
      case -1:
        queryOPT = null;
        break;

      case 0:
        queryOPT = new OPTRecord(0, 0, version, flags, options);
        break;

      default:
        throw new IllegalArgumentException("invalid EDNS version - must be 0 or -1 to disable");
    }
  }

  @Override
  public void setTSIGKey(TSIG key) {
    this.tsig = key;
  }

  @Override
  public void setTimeout(Duration timeout) {
    this.timeout = timeout;
    httpClients.clear();
  }

  @Override
  public Duration getTimeout() {
    return timeout;
  }

  @Override
  public CompletionStage<Message> sendAsync(Message query) {
    return sendAsync(query, defaultExecutor);
  }

  @Override
  public CompletionStage<Message> sendAsync(Message query, Executor executor) {
    if (USE_HTTP_CLIENT) {
      return sendAsync11(query, executor);
    }

    return sendAsync8(query, executor);
  }

  private CompletionStage<Message> sendAsync8(final Message query, Executor executor) {
    byte[] queryBytes = prepareQuery(query).toWire();
    String url = getUrl(queryBytes);
    long startTime = System.nanoTime();
    return maxConcurrentRequests
        .acquire(timeout)
        .handleAsync(
            (permit, ex) -> {
              if (ex != null) {
                return this.<Message>timeoutFailedFuture(query, ex);
              } else {
                try {
                  SendAndGetMessageBytesResponse result =
                      sendAndGetMessageBytes(url, queryBytes, startTime);
                  Message response;
                  if (result.rc == Rcode.NOERROR) {
                    response = new Message(result.responseBytes);
                    verifyTSIG(query, response, result.responseBytes, tsig);
                  } else {
                    response = new Message(0);
                    response.getHeader().setRcode(result.rc);
                  }

                  response.setResolver(this);
                  return CompletableFuture.completedFuture(response);
                } catch (SocketTimeoutException e) {
                  return this.<Message>timeoutFailedFuture(query, e);
                } catch (IOException e) {
                  return this.<Message>failedFuture(e);
                } finally {
                  permit.release();
                }
              }
            },
            executor)
        .thenCompose(Function.identity());
  }

  @Value
  private static class SendAndGetMessageBytesResponse {
    int rc;
    byte[] responseBytes;
  }

  private SendAndGetMessageBytesResponse sendAndGetMessageBytes(
      String url, byte[] queryBytes, long startTime) throws IOException {
    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
    if (conn instanceof HttpsURLConnection) {
      ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
    }

    Duration remainingTimeout = timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS);
    conn.setConnectTimeout((int) remainingTimeout.toMillis());
    conn.setReadTimeout((int) remainingTimeout.toMillis());
    conn.setRequestMethod(usePost ? "POST" : "GET");
    conn.setRequestProperty("Content-Type", APPLICATION_DNS_MESSAGE);
    conn.setRequestProperty("Accept", APPLICATION_DNS_MESSAGE);
    if (usePost) {
      conn.setDoOutput(true);
      conn.getOutputStream().write(queryBytes);
    }

    int rc = conn.getResponseCode();
    if (rc < 200 || rc >= 300) {
      discardStream(conn.getInputStream());
      discardStream(conn.getErrorStream());
      return new SendAndGetMessageBytesResponse(Rcode.SERVFAIL, null);
    }

    try (InputStream is = conn.getInputStream()) {
      int length = conn.getContentLength();
      if (length > -1) {
        byte[] responseBytes = new byte[conn.getContentLength()];
        int r;
        int offset = 0;
        while ((r = is.read(responseBytes, offset, responseBytes.length - offset)) > 0) {
          offset += r;
          remainingTimeout = timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS);
          if (remainingTimeout.isNegative()) {
            throw new SocketTimeoutException();
          }
        }
        if (offset < responseBytes.length) {
          throw new EOFException("Could not read expected content length");
        }
        return new SendAndGetMessageBytesResponse(Rcode.NOERROR, responseBytes);
      } else {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
          byte[] buffer = new byte[4096];
          int r;
          while ((r = is.read(buffer, 0, buffer.length)) > 0) {
            remainingTimeout = timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS);
            if (remainingTimeout.isNegative()) {
              throw new SocketTimeoutException();
            }
            bos.write(buffer, 0, r);
          }
          return new SendAndGetMessageBytesResponse(Rcode.NOERROR, bos.toByteArray());
        }
      }
    } catch (IOException ioe) {
      discardStream(conn.getErrorStream());
      throw ioe;
    }
  }

  private void discardStream(InputStream es) throws IOException {
    if (es != null) {
      try (InputStream in = es) {
        byte[] buf = new byte[4096];
        while (in.read(buf) > 0) {
          // discard
        }
      } catch (IOException ioe) {
        // ignore
      }
    }
  }

  private CompletionStage<Message> sendAsync11(final Message query, Executor executor) {
    long startTime = System.nanoTime();
    byte[] queryBytes = prepareQuery(query).toWire();
    String url = getUrl(queryBytes);

    // var requestBuilder = defaultHttpRequestBuilder.copy();
    // requestBuilder.uri(URI.create(url));
    Object requestBuilder;
    try {
      requestBuilder = requestBuilderCopyMethod.invoke(defaultHttpRequestBuilder);
      requestBuilderUriMethod.invoke(requestBuilder, URI.create(url));
      if (usePost) {
        // requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(queryBytes));
        requestBuilderPostMethod.invoke(
            requestBuilder, publisherOfByteArrayMethod.invoke(null, queryBytes));
      }
    } catch (IllegalAccessException | InvocationTargetException e) {
      return failedFuture(e);
    }

    // check if this request needs to be done synchronously because of HttpClient's stupidity to
    // not use the connection pool for HTTP/2 until one connection is successfully established,
    // which could lead to hundreds of connections (and threads with the default executor)
    Duration remainingTimeout = timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS);
    return initialRequestLock
        .acquire(remainingTimeout)
        .handle(
            (initialRequestPermit, initialRequestEx) -> {
              if (initialRequestEx != null) {
                return this.<Message>timeoutFailedFuture(query, initialRequestEx);
              } else {
                return sendAsync11WithInitialRequestPermit(
                    query, executor, startTime, requestBuilder, initialRequestPermit);
              }
            })
        .thenCompose(Function.identity());
  }

  private CompletionStage<Message> sendAsync11WithInitialRequestPermit(
      Message query,
      Executor executor,
      long startTime,
      Object requestBuilder,
      Permit initialRequestPermit) {
    long lastRequestTime = lastRequest.get();
    boolean isInitialRequest =
        (lastRequestTime < System.nanoTime() - idleConnectionTimeout.toNanos());
    if (!isInitialRequest) {
      initialRequestPermit.release();
    }

    // check if we already exceeded the query timeout while checking the initial connection
    Duration remainingTimeout = timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.isNegative()) {
      if (isInitialRequest) {
        initialRequestPermit.release();
      }
      return timeoutFailedFuture(query, null);
    }

    // Lock a HTTP/2 stream. Another stupidity of HttpClient to not simply queue the
    // request, but fail with an IOException which also CLOSES the connection... *facepalm*
    return maxConcurrentRequests
        .acquire(remainingTimeout)
        .handle(
            (maxConcurrentRequestPermit, maxConcurrentRequestEx) -> {
              if (maxConcurrentRequestEx != null) {
                if (isInitialRequest) {
                  initialRequestPermit.release();
                }
                return this.<Message>timeoutFailedFuture(query, maxConcurrentRequestEx);
              } else {
                return sendAsync11WithConcurrentRequestPermit(
                    query,
                    executor,
                    startTime,
                    requestBuilder,
                    initialRequestPermit,
                    isInitialRequest,
                    maxConcurrentRequestPermit);
              }
            })
        .thenCompose(Function.identity());
  }

  private CompletionStage<Message> sendAsync11WithConcurrentRequestPermit(
      Message query,
      Executor executor,
      long startTime,
      Object requestBuilder,
      Permit initialRequestPermit,
      boolean isInitialRequest,
      Permit maxConcurrentRequestPermit) {
    // check if the stream lock acquisition took too long
    Duration remainingTimeout = timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.isNegative()) {
      if (isInitialRequest) {
        initialRequestPermit.release();
      }
      maxConcurrentRequestPermit.release();
      return timeoutFailedFuture(query, null);
    }

    // var httpRequest = requestBuilder.timeout(remainingTimeout).build();
    // var bodyHandler = HttpResponse.BodyHandlers.ofByteArray();
    // return getHttpClient(executor).sendAsync(httpRequest, bodyHandler)
    try {
      Object httpClient = getHttpClient(executor);
      requestBuilderTimeoutMethod.invoke(requestBuilder, remainingTimeout);
      Object httpRequest = requestBuilderBuildMethod.invoke(requestBuilder);
      Object bodyHandler = byteArrayBodyPublisherMethod.invoke(null);
      CompletableFuture<Message> f =
          ((CompletableFuture<?>)
                  httpClientSendAsyncMethod.invoke(httpClient, httpRequest, bodyHandler))
              .whenComplete(
                  (result, ex) -> {
                    if (ex == null) {
                      lastRequest.set(startTime);
                    }
                    maxConcurrentRequestPermit.release();
                    if (isInitialRequest) {
                      initialRequestPermit.release();
                    }
                  })
              .handleAsync(
                  (response, ex) -> {
                    if (ex != null) {
                      if (ex.getCause().getClass().getSimpleName().equals("HttpTimeoutException")) {
                        return this.<Message>timeoutFailedFuture(query, ex.getCause());
                      } else {
                        return this.<Message>failedFuture(ex);
                      }
                    } else {
                      try {
                        Message responseMessage;
                        // int rc = response.statusCode();
                        int rc = (int) httpResponseStatusCodeMethod.invoke(response);
                        if (rc >= 200 && rc < 300) {
                          // byte[] responseBytes = response.body();
                          byte[] responseBytes = (byte[]) httpResponseBodyMethod.invoke(response);
                          responseMessage = new Message(responseBytes);
                          verifyTSIG(query, responseMessage, responseBytes, tsig);
                        } else {
                          responseMessage = new Message();
                          responseMessage.getHeader().setRcode(Rcode.SERVFAIL);
                        }

                        responseMessage.setResolver(this);
                        return CompletableFuture.completedFuture(responseMessage);
                      } catch (IOException | IllegalAccessException | InvocationTargetException e) {
                        return this.<Message>failedFuture(e);
                      }
                    }
                  },
                  executor)
              .thenCompose(Function.identity());
      return TimeoutCompletableFuture.compatTimeout(
          f, remainingTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (IllegalAccessException | InvocationTargetException e) {
      return failedFuture(e);
    }
  }

  private <T> CompletableFuture<T> failedFuture(Throwable e) {
    CompletableFuture<T> f = new CompletableFuture<>();
    f.completeExceptionally(e);
    return f;
  }

  private <T> CompletableFuture<T> timeoutFailedFuture(Message query, Throwable inner) {
    return failedFuture(
        new IOException(
            "Query "
                + query.getHeader().getID()
                + " for "
                + query.getQuestion().getName()
                + "/"
                + Type.string(query.getQuestion().getType())
                + " timed out",
            inner));
  }

  private String getUrl(byte[] queryBytes) {
    String url = uriTemplate;
    if (!usePost) {
      url += "?dns=" + base64.toString(queryBytes, true);
    }
    return url;
  }

  private Message prepareQuery(Message query) {
    Message preparedQuery = query.clone();
    preparedQuery.getHeader().setID(0);
    if (queryOPT != null && preparedQuery.getOPT() == null) {
      preparedQuery.addRecord(queryOPT, Section.ADDITIONAL);
    }

    if (tsig != null) {
      tsig.apply(preparedQuery, null);
    }

    return preparedQuery;
  }

  private void verifyTSIG(Message query, Message response, byte[] b, TSIG tsig) {
    if (tsig == null) {
      return;
    }

    int error = tsig.verify(response, b, query.getTSIG());
    log.debug(
        "TSIG verify for query {}, {}/{}: {}",
        query.getHeader().getID(),
        query.getQuestion().getName(),
        Type.string(query.getQuestion().getType()),
        Rcode.TSIGstring(error));
  }

  /** Returns {@code true} if the HTTP method POST to resolve, {@code false} if GET is used. */
  public boolean isUsePost() {
    return usePost;
  }

  /**
   * Sets the HTTP method to use for resolving.
   *
   * @param usePost {@code true} to use POST, {@code false} to use GET (the default).
   */
  public void setUsePost(boolean usePost) {
    this.usePost = usePost;
  }

  /** Gets the current URI used for resolving. */
  public String getUriTemplate() {
    return uriTemplate;
  }

  /** Sets the URI to use for resolving, e.g. {@code https://dns.google/dns-query} */
  public void setUriTemplate(String uriTemplate) {
    this.uriTemplate = uriTemplate;
  }

  /**
   * Gets the default {@link Executor} for request handling, defaults to {@link
   * ForkJoinPool#commonPool()}.
   *
   * @since 3.3
   * @deprecated not applicable if {@link #sendAsync(Message, Executor)} is used.
   */
  @Deprecated
  public Executor getExecutor() {
    return defaultExecutor;
  }

  /**
   * Sets the default {@link Executor} for request handling.
   *
   * @param executor The new {@link Executor}, can be {@code null} (which is equivalent to {@link
   *     ForkJoinPool#commonPool()}).
   * @since 3.3
   * @deprecated Use {@link #sendAsync(Message, Executor)}.
   */
  @Deprecated
  public void setExecutor(Executor executor) {
    this.defaultExecutor = executor == null ? ForkJoinPool.commonPool() : executor;
    httpClients.clear();
  }

  @Override
  public String toString() {
    return "DohResolver {" + (usePost ? "POST " : "GET ") + uriTemplate + "}";
  }
}

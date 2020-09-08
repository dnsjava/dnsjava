// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ForkJoinPool;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.base64;

/**
 * Implements a very basic DNS over HTTP (DoH) resolver. On Java 8, it uses HTTP/1.1, which is
 * against the recommendation of RFC 8484 to use HTTP/2 and thus horribly slow. On Java 11 or newer,
 * HTTP/2 is always used.
 */
@Slf4j
public final class DohResolver implements Resolver {
  private static final boolean useHttpClient;

  private static final int MAX_DOH_RESPONSE_SIZE = 2048;

  private static Object defaultHttpRequestBuilder;
  private static Method publisherOfByteArrayMethod;
  private static Method requestBuilderTimeoutMethod;
  private static Method requestBuilderCopyMethod;
  private static Method requestBuilderUriMethod;
  private static Method requestBuilderBuildMethod;
  private static Method requestBuilderPostMethod;

  private static Method httpClientNewBuilderMethod;
  private static Method httpClientBuilderTimeoutMethod;
  private static Method httpClientBuilderBuildMethod;
  private static Method httpClientSendAsyncMethod;

  private static Method byteArrayBodyPublisherMethod;
  private static Method httpResponseBodyMethod;
  private static Method httpResponseStatusCodeMethod;

  private boolean usePost = false;
  private Duration timeout = Duration.ofSeconds(5);
  private String uriTemplate;
  private OPTRecord queryOPT = new OPTRecord(0, 0, 0);
  private TSIG tsig;
  private Object httpClient;

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
        // defaultHttpRequestBuilder.version(Version.HTTP_2);
        // defaultHttpRequestBuilder.header("Content-Type", "application/dns-message");
        // defaultHttpRequestBuilder.header("Accept", "application/dns-message");
        defaultHttpRequestBuilder = requestBuilderNewBuilderMethod.invoke(null);
        @SuppressWarnings({"unchecked", "rawtypes"})
        Enum<?> http2Version = Enum.valueOf((Class<Enum>) httpVersionEnum, "HTTP_2");
        requestBuilderVersionMethod.invoke(defaultHttpRequestBuilder, http2Version);
        requestBuilderHeaderMethod.invoke(
            defaultHttpRequestBuilder, "Content-Type", "application/dns-message");
        requestBuilderHeaderMethod.invoke(
            defaultHttpRequestBuilder, "Accept", "application/dns-message");
        initSuccess = true;
      } catch (ClassNotFoundException
          | NoSuchMethodException
          | IllegalAccessException
          | InvocationTargetException e) {
        // fallback to Java 8
        log.warn("Java >= 11 detected, but HttpRequest not available");
      }
    }

    useHttpClient = initSuccess;
  }

  /**
   * Creates a new DoH resolver that performs lookups with HTTP GET and the default timeout (5s).
   *
   * @param uriTemplate the URI to use for resolving, e.g. {@code https://dns.google/dns-query}
   */
  public DohResolver(String uriTemplate) {
    this.uriTemplate = uriTemplate;
    buildHttpClient();
  }

  @SneakyThrows
  private void buildHttpClient() {
    if (useHttpClient) {
      Object httpClientBuilder = httpClientNewBuilderMethod.invoke(null);
      httpClientBuilderTimeoutMethod.invoke(httpClientBuilder, timeout);
      httpClient = httpClientBuilderBuildMethod.invoke(httpClientBuilder);
      requestBuilderTimeoutMethod.invoke(defaultHttpRequestBuilder, timeout);
    }
  }

  /** Not implemented. Specify the port in {@link #setUriTemplate(String)} if required. */
  @Override
  public void setPort(int port) {}

  /** Not implemented. */
  @Override
  public void setTCP(boolean flag) {}

  /** Not implemented. */
  @Override
  public void setIgnoreTruncation(boolean flag) {}

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
    buildHttpClient();
  }

  @Override
  public Duration getTimeout() {
    return timeout;
  }

  @Override
  public CompletionStage<Message> sendAsync(Message query) {
    if (useHttpClient) {
      return sendAsync11(query);
    }

    return sendAsync8(query);
  }

  private CompletionStage<Message> sendAsync8(final Message query) {
    CompletableFuture<Message> f = new CompletableFuture<>();
    ForkJoinPool.commonPool()
        .execute(
            () -> {
              try {
                byte[] queryBytes = prepareQuery(query).toWire();
                String url = getUrl(queryBytes);

                byte[] responseBytes = sendAndGetMessageBytes(url, queryBytes);
                Message response = new Message(responseBytes);
                verifyTSIG(query, response, responseBytes, tsig);
                response.setResolver(this);
                f.complete(response);
              } catch (IOException e) {
                f.completeExceptionally(e);
              }
            });
    return f;
  }

  private byte[] sendAndGetMessageBytes(String url, byte[] queryBytes) throws IOException {
    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
    conn.setConnectTimeout((int) timeout.toMillis());
    conn.setRequestMethod(isUsePost() ? "POST" : "GET");
    conn.setRequestProperty("Content-Type", "application/dns-message");
    conn.setRequestProperty("Accept", "application/dns-message");
    if (usePost) {
      conn.setDoOutput(true);
      conn.getOutputStream().write(queryBytes);
    }
    InputStream is = conn.getInputStream();
    final int contentLength = conn.getContentLength();
    int r;
    int offset = 0;
    byte[] responseBytes;

    // getContentLength() can return -1 in some cases if the length is unknown.
    if (contentLength > -1) {
      responseBytes = new byte[contentLength];

      // As bytes are read the available space in responseBytes reduces, so the 3rd parameter should
      // reduce accordingly.
      while ((r = is.read(responseBytes, offset, responseBytes.length - offset)) > 0) {
        offset += r;
      }
      return responseBytes;
    } else {
      // The response length is unknown, so read until we get a response of -1
      responseBytes = new byte[MAX_DOH_RESPONSE_SIZE];

      // As bytes are read the available space in responseBytes reduces, so the 3rd parameter should
      // reduce accordingly.
      while ((r = is.read(responseBytes, offset, responseBytes.length - offset)) > 0) {
        offset += r;
      }

      // Only return the bytes we actually read, not MAX_DOH_RESPONSE_SIZE bytes
      return Arrays.copyOfRange(responseBytes, 0, offset);
    }
  }

  private CompletionStage<Message> sendAsync11(final Message query) {
    byte[] queryBytes = prepareQuery(query).toWire();
    String url = getUrl(queryBytes);

    try {
      // var builder = defaultHttpRequestBuilder.copy();
      Object builder = requestBuilderCopyMethod.invoke(defaultHttpRequestBuilder);
      // builder.uri(URI.create(url));
      requestBuilderUriMethod.invoke(builder, URI.create(url));
      if (usePost) {
        // builder.POST(BodyPublishers.ofByteArray(queryBytes));
        requestBuilderPostMethod.invoke(
            builder, publisherOfByteArrayMethod.invoke(null, queryBytes));
      }

      // var request = request.build();
      // var bodyHandler = BodyHandlers.ofByteArray();
      Object httpRequest = requestBuilderBuildMethod.invoke(builder);
      Object bodyHandler = byteArrayBodyPublisherMethod.invoke(null);
      return ((CompletionStage<?>)
              httpClientSendAsyncMethod.invoke(httpClient, httpRequest, bodyHandler))
          .thenComposeAsync(
              response -> {
                try {
                  Message responseMessage;
                  if ((int) httpResponseStatusCodeMethod.invoke(response) == 200) {
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
                  return failedFuture(e);
                }
              });
    } catch (IllegalAccessException | InvocationTargetException e) {
      return failedFuture(e);
    }
  }

  private <T> CompletionStage<T> failedFuture(Throwable e) {
    CompletableFuture<T> f = new CompletableFuture<>();
    f.completeExceptionally(e);
    return f;
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
    log.debug("TSIG verify: {}", Rcode.TSIGstring(error));
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

  @Override
  public String toString() {
    return "DohResolver {" + (usePost ? "POST " : "GET ") + uriTemplate + "}";
  }
}

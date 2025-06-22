// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.AsyncSemaphore.Permit;

/**
 * Proof-of-concept <a href="https://datatracker.ietf.org/doc/html/rfc8484">DNS over HTTP (DoH)</a>
 * resolver. This class is not suitable for high load scenarios because of the shortcomings of
 * Java's built-in HTTP clients. For more control, implement your own {@link Resolver} using e.g. <a
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
public final class DohResolver extends DohResolverCommon {
  private static final String APPLICATION_DNS_MESSAGE = "application/dns-message";
  private static final Map<Executor, HttpClient> httpClients =
      Collections.synchronizedMap(new WeakHashMap<>());
  private static final HttpRequest.Builder defaultHttpRequestBuilder;

  private final AsyncSemaphore initialRequestLock = new AsyncSemaphore(1, "initial request");

  private final Duration idleConnectionTimeout;

  static {
    defaultHttpRequestBuilder = HttpRequest.newBuilder();
    defaultHttpRequestBuilder.version(HttpClient.Version.HTTP_2);
    defaultHttpRequestBuilder.header("Content-Type", APPLICATION_DNS_MESSAGE);
    defaultHttpRequestBuilder.header("Accept", APPLICATION_DNS_MESSAGE);
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
    super(uriTemplate, maxConcurrentRequests);
    log.debug("Using Java 11+ implementation");
    this.idleConnectionTimeout = idleConnectionTimeout;
  }

  @SneakyThrows
  private HttpClient getHttpClient(Executor executor) {
    return httpClients.computeIfAbsent(
        executor,
        key -> {
          try {
            return HttpClient.newBuilder().connectTimeout(timeout).executor(executor).build();
          } catch (IllegalArgumentException e) {
            log.warn("Could not create a HttpClient for Executor {}", key, e);
            return null;
          }
        });
  }

  @Override
  public void setTimeout(Duration timeout) {
    this.timeout = timeout;
    httpClients.clear();
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
  @SuppressWarnings("java:S1185") // required for source- and binary compatibility
  public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
    // required for source- and binary compatibility
    super.setEDNS(version, payloadSize, flags, options);
  }

  @Override
  @SuppressWarnings("java:S1185") // required for source- and binary compatibility
  public CompletionStage<Message> sendAsync(Message query) {
    return this.sendAsync(query, defaultExecutor);
  }

  @Override
  public CompletionStage<Message> sendAsync(Message query, Executor executor) {
    long startTime = getNanoTime();
    byte[] queryBytes = prepareQuery(query).toWire();
    String url = getUrl(queryBytes);

    var requestBuilder = defaultHttpRequestBuilder.copy();
    requestBuilder.uri(URI.create(url));
    if (usePost) {
      requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(queryBytes));
    }

    // check if this request needs to be done synchronously because of HttpClient's stupidity to
    // not use the connection pool for HTTP/2 until one connection is successfully established,
    // which could lead to hundreds of connections (and threads with the default executor)
    Duration remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.toMillis() <= 0) {
      return timeoutFailedFuture(query, "no time left to acquire lock for first request", null);
    }

    return initialRequestLock
        .acquire(remainingTimeout, query.getHeader().getID(), executor)
        .handle(
            (initialRequestPermit, initialRequestEx) -> {
              if (initialRequestEx != null) {
                return this.<Message>timeoutFailedFuture(query, initialRequestEx);
              } else {
                return sendAsyncWithInitialRequestPermit(
                    query, executor, startTime, requestBuilder, initialRequestPermit);
              }
            })
        .thenCompose(Function.identity());
  }

  private CompletionStage<Message> sendAsyncWithInitialRequestPermit(
      Message query,
      Executor executor,
      long startTime,
      HttpRequest.Builder requestBuilder,
      Permit initialRequestPermit) {
    int queryId = query.getHeader().getID();
    long lastRequestTime = lastRequest.get();
    long requestDeltaNanos = getNanoTime() - lastRequestTime;
    boolean isInitialRequest =
        lastRequestTime == 0 || idleConnectionTimeout.toNanos() < requestDeltaNanos;
    if (!isInitialRequest) {
      initialRequestPermit.release(queryId, executor);
    }

    // check if we already exceeded the query timeout while checking the initial connection
    Duration remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.toMillis() <= 0) {
      if (isInitialRequest) {
        initialRequestPermit.release(queryId, executor);
      }

      return timeoutFailedFuture(
          query, "no time left to acquire lock for concurrent request", null);
    }

    // Lock a HTTP/2 stream. Another stupidity of HttpClient to not simply queue the
    // request, but fail with an IOException which also CLOSES the connection... *facepalm*
    return maxConcurrentRequests
        .acquire(remainingTimeout, queryId, executor)
        .handle(
            (maxConcurrentRequestPermit, maxConcurrentRequestEx) -> {
              if (maxConcurrentRequestEx != null) {
                if (isInitialRequest) {
                  initialRequestPermit.release(queryId, executor);
                }
                return this.<Message>timeoutFailedFuture(
                    query,
                    "timed out waiting for a concurrent request lease",
                    maxConcurrentRequestEx);
              } else {
                return sendAsyncWithConcurrentRequestPermit(
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

  private CompletionStage<Message> sendAsyncWithConcurrentRequestPermit(
      Message query,
      Executor executor,
      long startTime,
      HttpRequest.Builder requestBuilder,
      Permit initialRequestPermit,
      boolean isInitialRequest,
      Permit maxConcurrentRequestPermit) {
    int queryId = query.getHeader().getID();

    // check if the stream lock acquisition took too long
    Duration remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.toMillis() <= 0) {
      if (isInitialRequest) {
        initialRequestPermit.release(queryId, executor);
      }

      maxConcurrentRequestPermit.release(queryId, executor);
      return timeoutFailedFuture(
          query, "no time left to acquire lock for concurrent request", null);
    }

    var httpRequest = requestBuilder.timeout(remainingTimeout).build();
    var bodyHandler = HttpResponse.BodyHandlers.ofByteArray();
    return getHttpClient(executor)
        .sendAsync(httpRequest, bodyHandler)
        .whenComplete(
            (result, ex) -> {
              if (ex == null) {
                lastRequest.set(startTime);
              }
              maxConcurrentRequestPermit.release(queryId, executor);
              if (isInitialRequest) {
                initialRequestPermit.release(queryId, executor);
              }
            })
        .handleAsync(
            (response, ex) -> {
              if (ex != null) {
                if (ex instanceof HttpTimeoutException) {
                  return this.<Message>timeoutFailedFuture(
                      query, "http request did not complete", ex.getCause());
                } else {
                  return CompletableFuture.<Message>failedFuture(ex);
                }
              } else {
                try {
                  Message responseMessage;
                  int rc = response.statusCode();
                  if (rc >= 200 && rc < 300) {
                    byte[] responseBytes = response.body();
                    responseMessage = new Message(responseBytes);
                    verifyTSIG(query, responseMessage, responseBytes, tsig);
                  } else {
                    responseMessage = new Message();
                    responseMessage.getHeader().setRcode(Rcode.SERVFAIL);
                  }

                  responseMessage.setResolver(this);
                  return CompletableFuture.completedFuture(responseMessage);
                } catch (IOException e) {
                  return CompletableFuture.<Message>failedFuture(e);
                }
              }
            },
            executor)
        .thenCompose(Function.identity())
        .orTimeout(remainingTimeout.toMillis(), TimeUnit.MILLISECONDS)
        .exceptionally(
            ex -> {
              if (ex instanceof TimeoutException) {
                throw new CompletionException(
                    new TimeoutException(
                        "Query "
                            + query.getHeader().getID()
                            + " for "
                            + query.getQuestion().getName()
                            + "/"
                            + Type.string(query.getQuestion().getType())
                            + " timed out in remaining "
                            + remainingTimeout.toMillis()
                            + "ms"));
              } else if (ex instanceof CompletionException) {
                throw (CompletionException) ex;
              }

              throw new CompletionException(ex);
            });
  }

  @Override
  protected <T> CompletableFuture<T> failedFuture(Throwable e) {
    return CompletableFuture.failedFuture(e);
  }
}

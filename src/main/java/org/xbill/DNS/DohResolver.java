// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

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
  private final SSLSocketFactory sslSocketFactory;

  /**
   * Creates a new DoH resolver that performs lookups with HTTP GET and the default timeout (5s).
   *
   * @param uriTemplate the URI to use for resolving, e.g. {@code https://dns.google/dns-query}
   */
  public DohResolver(String uriTemplate) {
    this(uriTemplate, 100, Duration.ZERO);
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

    log.debug("Using Java 8 implementation");
    try {
      sslSocketFactory = SSLContext.getDefault().getSocketFactory();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
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
    // required for source- and binary compatibility
    return this.sendAsync(query, defaultExecutor);
  }

  @Override
  public CompletionStage<Message> sendAsync(Message query, Executor executor) {
    byte[] queryBytes = prepareQuery(query).toWire();
    String url = getUrl(queryBytes);
    long startTime = getNanoTime();
    int queryId = query.getHeader().getID();

    CompletableFuture<Message> f =
        maxConcurrentRequests
            .acquire(timeout, queryId, executor)
            .handleAsync(
                (permit, ex) -> {
                  if (ex != null) {
                    return this.<Message>timeoutFailedFuture(
                        query, "could not acquire lock to send request", ex);
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
                    } catch (IOException | URISyntaxException e) {
                      return this.<Message>failedFuture(e);
                    } finally {
                      permit.release(queryId, executor);
                    }
                  }
                },
                executor)
            .thenCompose(Function.identity())
            .toCompletableFuture();

    Duration remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
    return TimeoutCompletableFuture.compatTimeout(
            f, remainingTimeout.toMillis(), TimeUnit.MILLISECONDS)
        .exceptionally(
            ex -> {
              if (ex instanceof TimeoutException) {
                throw new CompletionException(
                    new TimeoutException(
                        "Query "
                            + queryId
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

  @Value
  private static class SendAndGetMessageBytesResponse {
    int rc;
    byte[] responseBytes;
  }

  private SendAndGetMessageBytesResponse sendAndGetMessageBytes(
      String url, byte[] queryBytes, long startTime) throws IOException, URISyntaxException {
    HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
    if (conn instanceof HttpsURLConnection) {
      ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
    }
    conn.setRequestMethod(usePost ? "POST" : "GET");
    conn.setRequestProperty("Content-Type", APPLICATION_DNS_MESSAGE);
    conn.setRequestProperty("Accept", APPLICATION_DNS_MESSAGE);

    Duration remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.toMillis() <= 0) {
      throw new SocketTimeoutException("No time left to connect");
    }

    conn.setConnectTimeout((int) remainingTimeout.toMillis());
    if (usePost) {
      conn.setDoOutput(true);
    }

    conn.connect();
    remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
    if (remainingTimeout.toMillis() <= 0) {
      throw new SocketTimeoutException("No time left to request data");
    }

    conn.setReadTimeout((int) remainingTimeout.toMillis());
    if (usePost) {
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
          remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);

          // Don't throw if we just received all data
          if (offset != responseBytes.length
              && (remainingTimeout.isNegative() || remainingTimeout.isZero())) {
            throw new SocketTimeoutException(
                "Timed out waiting for response data, got "
                    + offset
                    + " of "
                    + responseBytes.length
                    + " expected bytes");
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
            remainingTimeout = timeout.minus(getNanoTime() - startTime, ChronoUnit.NANOS);
            if (remainingTimeout.isNegative() || remainingTimeout.isZero()) {
              throw new SocketTimeoutException(
                  "Timed out waiting for response data, got " + bos.size() + " bytes so far");
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

  @Override
  protected <T> CompletableFuture<T> failedFuture(Throwable e) {
    CompletableFuture<T> f = new CompletableFuture<>();
    f.completeExceptionally(e);
    return f;
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.base64;

@Slf4j
abstract class DohResolverCommon implements Resolver {
  /**
   * Maximum concurrent HTTP/2 streams or HTTP/1.1 connections.
   *
   * <p>rfc7540#section-6.5.2 recommends a minimum of 100 streams for HTTP/2.
   */
  protected final AsyncSemaphore maxConcurrentRequests;

  protected final AtomicLong lastRequest = new AtomicLong(0);

  protected static final String APPLICATION_DNS_MESSAGE = "application/dns-message";

  protected boolean usePost = false;
  protected Duration timeout = Duration.ofSeconds(5);
  protected String uriTemplate;
  protected OPTRecord queryOPT = new OPTRecord(0, 0, 0);
  protected TSIG tsig;
  protected Executor defaultExecutor = ForkJoinPool.commonPool();

  // package-visible for testing
  long getNanoTime() {
    return System.nanoTime();
  }

  /**
   * Creates a new DoH resolver that performs lookups with HTTP GET and the default timeout (5s).
   *
   * @param uriTemplate the URI to use for resolving, e.g. {@code https://dns.google/dns-query}
   * @param maxConcurrentRequests Maximum concurrent HTTP/2 streams for Java 11+ or HTTP/1.1
   *     connections for Java 8. On Java 8 this cannot exceed the system property {@code
   *     http.maxConnections}.
   */
  protected DohResolverCommon(String uriTemplate, int maxConcurrentRequests) {
    this.uriTemplate = uriTemplate;
    if (maxConcurrentRequests <= 0) {
      throw new IllegalArgumentException("maxConcurrentRequests must be > 0");
    }

    try {
      int javaMaxConn = Integer.parseInt(System.getProperty("http.maxConnections", "5"));
      if (maxConcurrentRequests > javaMaxConn) {
        maxConcurrentRequests = javaMaxConn;
      }
    } catch (NumberFormatException nfe) {
      // well, use what we got
    }

    this.maxConcurrentRequests =
        new AsyncSemaphore(maxConcurrentRequests, "concurrent request limit");
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
  }

  @Override
  public Duration getTimeout() {
    return timeout;
  }

  protected String getUrl(byte[] queryBytes) {
    String url = uriTemplate;
    if (!usePost) {
      url += "?dns=" + base64.toString(queryBytes, true);
    }
    return url;
  }

  protected Message prepareQuery(Message query) {
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

  protected void verifyTSIG(Message query, Message response, byte[] b, TSIG tsig) {
    if (tsig == null) {
      return;
    }

    int error = tsig.verify(response, b, query.getGeneratedTSIG());
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
  }

  @Override
  public String toString() {
    return "DohResolver {" + (usePost ? "POST " : "GET ") + uriTemplate + "}";
  }

  protected abstract <T> CompletableFuture<T> failedFuture(Throwable e);

  protected final <T> CompletableFuture<T> timeoutFailedFuture(Message query, Throwable inner) {
    return timeoutFailedFuture(query, null, inner);
  }

  protected final <T> CompletableFuture<T> timeoutFailedFuture(
      Message query, String message, Throwable inner) {
    return failedFuture(
        new TimeoutException(
            "Query "
                + query.getHeader().getID()
                + " for "
                + query.getQuestion().getName()
                + "/"
                + Type.string(query.getQuestion().getType())
                + " timed out"
                + (message != null ? ": " + message : "")
                + (inner != null && inner.getMessage() != null ? ", " + inner.getMessage() : "")));
  }
}

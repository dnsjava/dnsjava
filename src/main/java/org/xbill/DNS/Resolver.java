// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Interface describing a resolver.
 *
 * @author Brian Wellington
 */
public interface Resolver {

  /**
   * Sets the port to communicate with on the server
   *
   * @param port The port to send messages to
   */
  void setPort(int port);

  /**
   * Sets whether TCP connections will be used by default
   *
   * @param flag Indicates whether TCP connections are made
   */
  void setTCP(boolean flag);

  /**
   * Sets whether truncated responses will be ignored. If not, a truncated response over UDP will
   * cause a retransmission over TCP.
   *
   * @param flag Indicates whether truncated responses should be ignored.
   */
  void setIgnoreTruncation(boolean flag);

  /**
   * Sets the EDNS version used on outgoing messages.
   *
   * @param version The EDNS level to use. 0 indicates EDNS0 and -1 indicates no EDNS.
   * @throws IllegalArgumentException An invalid level was indicated.
   */
  default void setEDNS(int version) {
    setEDNS(version, 0, 0, Collections.emptyList());
  }

  /**
   * Sets the EDNS information on outgoing messages.
   *
   * @param version The EDNS version to use. 0 indicates EDNS0 and -1 indicates no EDNS.
   * @param payloadSize The maximum DNS packet size that this host is capable of receiving over UDP.
   *     If 0 is specified, the default ({@value
   *     org.xbill.DNS.SimpleResolver#DEFAULT_EDNS_PAYLOADSIZE}) is used.
   * @param flags EDNS extended flags to be set in the OPT record.
   * @param options EDNS options to be set in the OPT record, specified as a List of
   *     OPTRecord.Option elements.
   * @throws IllegalArgumentException An invalid field was specified.
   * @see OPTRecord
   */
  void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options);

  /**
   * Sets the EDNS information on outgoing messages.
   *
   * @param version The EDNS version to use. 0 indicates EDNS0 and -1 indicates no EDNS.
   * @param payloadSize The maximum DNS packet size that this host is capable of receiving over UDP.
   *     If 0 is specified, the default (1280) is used.
   * @param flags EDNS extended flags to be set in the OPT record.
   * @param options EDNS options to be set in the OPT record, specified as a List of
   *     OPTRecord.Option elements.
   * @throws IllegalArgumentException An invalid field was specified.
   * @see OPTRecord
   */
  default void setEDNS(int version, int payloadSize, int flags, EDNSOption... options) {
    setEDNS(
        version,
        payloadSize,
        flags,
        options == null ? Collections.emptyList() : Arrays.asList(options));
  }

  /**
   * Specifies the TSIG key that messages will be signed with
   *
   * @param key The key
   */
  void setTSIGKey(TSIG key);

  /**
   * Sets the amount of time to wait for a response before giving up.
   *
   * @param secs The number of seconds to wait.
   * @param msecs The number of milliseconds to wait.
   * @deprecated use {@link #setTimeout(Duration)}
   */
  @Deprecated
  default void setTimeout(int secs, int msecs) {
    setTimeout(Duration.ofMillis(secs * 1000 + msecs));
  }

  /**
   * Sets the amount of time to wait for a response before giving up.
   *
   * @param secs The number of seconds to wait.
   * @deprecated use {@link #setTimeout(Duration)}
   */
  @Deprecated
  default void setTimeout(int secs) {
    setTimeout(Duration.ofSeconds(secs));
  }

  /**
   * Sets the amount of time to wait for a response before giving up.
   *
   * @param timeout The amount of time to wait.
   */
  void setTimeout(Duration timeout);

  /**
   * Gets the amount of time to wait for a response before giving up.
   *
   * @see #setTimeout(Duration)
   */
  default Duration getTimeout() {
    return Duration.ofSeconds(10);
  }

  /**
   * Sends a message and waits for a response.
   *
   * @param query The query to send.
   * @return The response
   * @throws IOException An error occurred while sending or receiving.
   */
  default Message send(Message query) throws IOException {
    try {
      CompletableFuture<Message> result = sendAsync(query).toCompletableFuture();
      return result.get(getTimeout().toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      throw new IOException(e);
    } catch (ExecutionException e) {
      if (e.getCause() instanceof IOException) {
        throw (IOException) e.getCause();
      } else {
        throw new IOException(e.getCause());
      }
    } catch (TimeoutException e) {
      throw new SocketTimeoutException(e.getMessage());
    }
  }

  /**
   * Asynchronously sends a message.
   *
   * <p>The default implementation calls the deprecated {@link #sendAsync(Message,
   * ResolverListener)}. Implementors must override at least one of the {@code sendAsync} methods or
   * a stack overflow will occur.
   *
   * @param query The query to send.
   * @return A future that completes when the query is finished.
   */
  @SuppressWarnings("deprecation")
  default CompletionStage<Message> sendAsync(Message query) {
    CompletableFuture<Message> f = new CompletableFuture<>();
    sendAsync(
        query,
        new ResolverListener() {
          @Override
          public void receiveMessage(Object id, Message m) {
            f.complete(m);
          }

          @Override
          public void handleException(Object id, Exception e) {
            f.completeExceptionally(e);
          }
        });
    return f;
  }

  /**
   * Asynchronously sends a message registering a listener to receive a callback on success or
   * exception. Multiple asynchronous lookups can be performed in parallel. The callback may be
   * invoked from any thread.
   *
   * <p>The default implementation calls {@link #sendAsync(Message)}. Implementors must override at
   * least one of the {@code sendAsync} methods or a stack overflow will occur.
   *
   * @param query The query to send
   * @param listener The object containing the callbacks.
   * @return An identifier, which is also a parameter in the callback
   * @deprecated Use {@link #sendAsync(Message)}
   */
  @Deprecated
  default Object sendAsync(Message query, ResolverListener listener) {
    final Object id = new Object();
    CompletionStage<Message> f = sendAsync(query);
    f.handleAsync(
        (result, throwable) -> {
          if (throwable != null) {
            Exception exception;
            if (throwable instanceof Exception) {
              exception = (Exception) throwable;
            } else {
              exception = new Exception(throwable);
            }
            listener.handleException(id, exception);
            return null;
          }

          listener.receiveMessage(id, result);
          return null;
        });
    return id;
  }
}

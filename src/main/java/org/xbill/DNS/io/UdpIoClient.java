// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.io;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.xbill.DNS.Message;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Socks5Proxy;

/**
 * Serves as an interface from a {@link Resolver} to the underlying mechanism for sending bytes over
 * the wire as a UDP message.
 *
 * @since 3.6
 */
public interface UdpIoClient {
  /**
   * Sends a query to a remote server and returns the answer.
   *
   * @param local Address from which the connection is coming. may be {@code null} and the
   *     implementation must decide on the local address.
   * @param remote Address that the connection should send the data to.
   * @param query DNS message representation of the outbound query.
   * @param data Raw byte representation of the outbound query.
   * @param max Size of the response buffer.
   * @param timeout Duration before the connection will time out and be closed.
   * @return A {@link CompletableFuture} that will be completed with the byte value of the response.
   * @since 3.6
   */
  CompletableFuture<byte[]> sendAndReceiveUdp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      int max,
      Duration timeout);

  CompletableFuture<byte[]> sendAndReceiveUdp(
    InetSocketAddress local,
    InetSocketAddress remote,
    Socks5Proxy proxy,
    Message query,
    byte[] data,
    int max,
    Duration timeout);
}

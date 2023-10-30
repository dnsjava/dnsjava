// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/** @since 3.6 */
public interface TcpResolverClient {

  /**
   * Serves as an interface from a resolver to the underlying mechanism for sending bytes over the
   * wire as a TCP message.
   *
   * @since 3.6
   * @param local address from which the connection is coming
   * @param remote address that the connection should send the data to
   * @param query DNS message representation of the outbound query
   * @param data raw byte representation of the outbound query
   * @param timeout in milliseconds before the connection will time out and be closed
   * @return a completable future that will be completed with the byte value of the response
   */
  CompletableFuture<byte[]> sendAndReceiveTcp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      Duration timeout);
}

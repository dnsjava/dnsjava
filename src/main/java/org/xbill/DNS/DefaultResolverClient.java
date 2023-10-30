// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * An implementation of the ResolverClient that serves as a bridge to the internal static instances
 * of the Nio clients.
 *
 * @see NioUdpClient
 * @see NioTcpClient
 * @since 3.6
 */
public class DefaultResolverClient implements TcpResolverClient, UdpResolverClient {

  @Override
  public CompletableFuture<byte[]> sendAndReceiveTcp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      Duration timeout) {
    return NioTcpClient.sendrecv(local, remote, query, data, timeout);
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveUdp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      int max,
      Duration timeout) {
    return NioUdpClient.sendrecv(local, remote, query, data, max, timeout);
  }
}

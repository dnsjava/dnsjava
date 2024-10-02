// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;

/**
 * An implementation of the IO clients that use the internal NIO-based clients.
 *
 * @see NioUdpClient
 * @see NioTcpClient
 * @since 3.6
 */
public class DefaultIoClient implements TcpIoClient, UdpIoClient {
  private final TcpIoClient tcpIoClient;
  private final UdpIoClient udpIoClient;

  public DefaultIoClient() {
    tcpIoClient = new NioTcpClient();
    udpIoClient = new NioUdpClient();
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveTcp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      Duration timeout) {
    return tcpIoClient.sendAndReceiveTcp(local, remote, query, data, timeout);
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveTcp(
    InetSocketAddress local,
    InetSocketAddress remote,
    Socks5Proxy proxy,
    Message query,
    byte[] data,
    Duration timeout) {
    return tcpIoClient.sendAndReceiveTcp(local, remote, proxy, query, data, timeout);
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveUdp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      int max,
      Duration timeout) {
    return udpIoClient.sendAndReceiveUdp(local, remote, query, data, max, timeout);
  }
}

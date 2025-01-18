// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.TcpIoClient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@Slf4j
final class NioSocksTcpClient extends NioTcpHandler implements TcpIoClient {
  // TCP handler
  private final NioTcpHandler tcpHandler;
  // SOCKS5 proxy configuration
  private final Socks5ProxyConfig socksConfig;

  NioSocksTcpClient(Socks5ProxyConfig config) {
    socksConfig = Objects.requireNonNull(config, "proxy config must not be null");
    tcpHandler = new NioTcpHandler();
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveTcp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      Duration timeout) {
    NioSocksHandler proxy = new NioSocksHandler(socksConfig.getProxyAddress(), remote, local, socksConfig.getSocks5User(), socksConfig.getSocks5Password());
    return tcpHandler.sendAndReceiveTcp(local, remote, proxy, query, data, timeout);
  }
}

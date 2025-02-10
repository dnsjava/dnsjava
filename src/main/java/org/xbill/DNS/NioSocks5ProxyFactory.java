// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.util.Objects;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.IoClientFactory;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;

@Getter
@Slf4j
public class NioSocks5ProxyFactory implements IoClientFactory {
  private final NioSocks5ProxyConfig config;
  private final TcpIoClient tcpIoClient;
  private final UdpIoClient udpIoClient;

  public NioSocks5ProxyFactory(NioSocks5ProxyConfig socks5Proxy) {
    config = Objects.requireNonNull(socks5Proxy, "proxy config must not be null");
    tcpIoClient = new NioSocksTcpClient(config);
    udpIoClient = new NioSocksUdpClient(config);
  }

  @Override
  public TcpIoClient createOrGetTcpClient() {
    return tcpIoClient;
  }

  @Override
  public UdpIoClient createOrGetUdpClient() {
    return udpIoClient;
  }
}

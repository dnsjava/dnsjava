package org.xbill.DNS;

import java.io.IOException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.IoClientFactory;
import org.xbill.DNS.io.TcpIoClient;
import org.xbill.DNS.io.UdpIoClient;

@Getter
@Slf4j
public class NioSocks5ProxyFactory implements IoClientFactory {

  // SOCKS5 proxy configuration
  private final Socks5ProxyConfig config;

  // io clients
  private final TcpIoClient tcpIoClient;
  private final UdpIoClient udpIoClient;

  // constructor
  public NioSocks5ProxyFactory(Socks5ProxyConfig socks5Proxy) {
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

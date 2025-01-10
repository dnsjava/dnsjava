// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.TcpIoClient;

@Slf4j
final class NioTcpClient extends NioTcpHandler implements TcpIoClient {
  NioTcpHandler tcpHandler;

  NioTcpClient() {
    tcpHandler = new NioTcpHandler();
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveTcp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      Duration timeout) {
    return tcpHandler.sendAndReceiveTcp(local, remote, null, query, data, timeout);
  }
}

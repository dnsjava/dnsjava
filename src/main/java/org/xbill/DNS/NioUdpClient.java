// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.UdpIoClient;

@Slf4j
final class NioUdpClient extends NioClient implements UdpIoClient {
  private final NioUdpHandler udpHandler;

  NioUdpClient() {
    udpHandler = new NioUdpHandler();
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveUdp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      int max,
      Duration timeout) {
    return udpHandler.sendAndReceiveUdp(local, remote, null, query, data, max, timeout);
  }

}

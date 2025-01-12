// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.UdpIoClient;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
final class NioSocksUdpClient extends NioClient implements UdpIoClient {
  private final NioTcpHandler tcpHandler = new NioTcpHandler();
  private final NioUdpHandler udpHandler = new NioUdpHandler();
  private final NioSocksUdpAssociateChannelPool udpPool = new NioSocksUdpAssociateChannelPool(tcpHandler, udpHandler);
  private final Socks5ProxyConfig socksConfig;

  NioSocksUdpClient(Socks5ProxyConfig config) {
    socksConfig = config;
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveUdp(
    InetSocketAddress local,
    InetSocketAddress remote,
    Message query,
    byte[] data,
    int max,
    Duration timeout) {
    CompletableFuture<byte[]> future = new CompletableFuture<>();
    long endTime = System.nanoTime() + timeout.toNanos();
    NioSocksHandler proxy = new NioSocksHandler(socksConfig.getProxyAddress(), remote, local);
    NioSocksUdpAssociateChannelPool.SocksUdpAssociateChannelState channel = udpPool.createOrGetChannelState(local, remote, proxy, future);

    synchronized (channel.getTcpChannel()) {
      if (channel.getTcpChannel().socks5HandshakeF == null
          || channel.getTcpChannel().socks5HandshakeF.isCompletedExceptionally()
          || !channel.isSocks5Initialized()) {
        channel.getTcpChannel().setSocks5(true);
        channel.getTcpChannel().socks5HandshakeF = proxy.doSocks5Handshake(
          channel.getTcpChannel(), NioSocksHandler.SOCKS5_CMD_UDP_ASSOCIATE, query, endTime);
      }
    }

    channel.getTcpChannel().socks5HandshakeF.thenApplyAsync(cmdBytes -> {
      channel.setSocks5Initialized(true);
      NioSocksHandler.CmdResponse cmd = new NioSocksHandler.CmdResponse(cmdBytes);
      InetSocketAddress newRemote = new InetSocketAddress(socksConfig.getProxyAddress().getAddress(), cmd.getPort());
      byte[] wrappedData = proxy.addUdpHeader(data, newRemote);

      udpHandler.sendAndReceiveUdp(local, newRemote, channel.getUdpChannel(), query, wrappedData, max, timeout)
        .thenApplyAsync(response -> {
          channel.setOccupied(false);
          if (response.length < 10) {
            future.completeExceptionally(new IllegalStateException("SOCKS5 UDP response too short"));
          } else {
            future.complete(proxy.removeUdpHeader(response));
          }
          return null;
        }).exceptionally(ex -> {
          future.completeExceptionally(ex);
          return null;
        });
      return null;
    }).exceptionally(ex -> {
      future.completeExceptionally(ex);
      return null;
    });

    return future;
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.UdpIoClient;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

@Slf4j
final class NioSocksUdpClient extends NioClient implements UdpIoClient {
  private final NioUdpHandler udpHandler = new NioUdpHandler();
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
    CompletableFuture<byte[]> f = new CompletableFuture<>();
    long endTime = System.nanoTime() + timeout.toNanos();
    NioSocksHandler proxy = new NioSocksHandler(socksConfig.getProxyAddress(), remote, local);
    NioSocksUdpAssociateChannelPool.SocksUdpAssociateChannelState channel = udpHandler.getUdpPool().createOrGetSocketChannelState(local, remote, proxy, f);

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
          try {
            f.complete(proxy.removeUdpHeader(response));
          } catch (IllegalArgumentException e) {
            f.completeExceptionally(e);
          }
          return null;
        }).exceptionally(ex -> {
          f.completeExceptionally(ex);
          return null;
        });
      return null;
    }).exceptionally(ex -> {
      f.completeExceptionally(ex);
      return null;
    });

    return f;
  }
}

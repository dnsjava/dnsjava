// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.UdpIoClient;

@Slf4j
final class NioSocksUdpClient extends NioClient implements UdpIoClient {
  private final NioUdpHandler udpHandler = new NioUdpHandler();
  private final NioSocks5ProxyConfig socksConfig;

  NioSocksUdpClient(NioSocks5ProxyConfig config) {
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
    NioSocksHandler proxy =
        new NioSocksHandler(
            socksConfig.getProxyAddress(),
            remote,
            local,
            socksConfig.getSocks5User(),
            socksConfig.getSocks5Password());
    NioSocksUdpAssociateChannelPool.SocksUdpAssociateChannelState channel =
        udpHandler.getUdpPool().createOrGetSocketChannelState(local, proxy.getProxyAddress(), f);

    synchronized (channel) {
      if (channel.getTcpChannel().socks5HandshakeF == null
          || channel.getTcpChannel().socks5HandshakeF.isCompletedExceptionally()) {
        channel.getTcpChannel().setSocks5(true);
        channel.getTcpChannel().socks5HandshakeF =
            proxy.doSocks5Handshake(
                channel.getTcpChannel(), NioSocksHandler.SOCKS5_CMD_UDP_ASSOCIATE, query, endTime);
      }
    }

    channel
        .getTcpChannel()
        .socks5HandshakeF
        .thenApplyAsync(
            cmdBytes -> {
              byte[] wrappedData = proxy.addUdpHeader(data);
              NioSocksHandler.CmdResponse cmd = new NioSocksHandler.CmdResponse(cmdBytes);
              InetSocketAddress newRemote =
                  new InetSocketAddress(socksConfig.getProxyAddress().getAddress(), cmd.getPort());
              udpHandler
                  .sendAndReceiveUdp(
                      local, newRemote, channel.getUdpChannel(), query, wrappedData, max, timeout)
                  .thenApplyAsync(
                      response -> {
                        channel.setOccupied(false);
                        try {
                          f.complete(proxy.removeUdpHeader(response));
                        } catch (IllegalArgumentException e) {
                          f.completeExceptionally(e);
                        }
                        return null;
                      })
                  .exceptionally(
                      ex -> {
                        channel.setFailed(true);
                        f.completeExceptionally(ex);
                        return null;
                      });
              return null;
            })
        .exceptionally(
            ex -> {
              channel.setFailed(true);
              f.completeExceptionally(ex);
              return null;
            });

    return f;
  }
}

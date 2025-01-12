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
    NioTcpHandler.ChannelState tcpChannel = tcpHandler.createOrGetChannelState(local, remote, proxy, future);

    synchronized (tcpChannel) {
      if (tcpChannel.socks5HandshakeF == null) {
        tcpChannel.setSocks5(true);
        tcpChannel.socks5HandshakeF = proxy.doSocks5Handshake(tcpChannel, NioSocksHandler.SOCKS5_CMD_UDP_ASSOCIATE, query, endTime);
      }
    }

    tcpChannel.socks5HandshakeF.thenApplyAsync(cmdBytes -> {
      NioSocksHandler.CmdResponse cmd = new NioSocksHandler.CmdResponse(cmdBytes);
      InetSocketAddress newRemote = new InetSocketAddress(socksConfig.getProxyAddress().getAddress(), cmd.getPort());
      byte[] wrappedData = proxy.addUdpHeader(data, newRemote);

      DatagramChannel udpChannel;
      udpChannel = channelMap.computeIfAbsent(newRemote.toString(), k -> {
        try {
          return udpHandler.createChannel(local, newRemote, future);
        } catch (Exception e) {
          future.completeExceptionally(e);
          return null;
        }
      });

      udpHandler.sendAndReceiveUdp(local, newRemote, udpChannel, query, wrappedData, max, timeout)
        .thenApplyAsync(response -> {
          if (response.length < 10) {
            channelMap.remove(newRemote.toString());
            future.completeExceptionally(new IllegalStateException("SOCKS5 UDP response too short"));
          } else {
            future.complete(proxy.removeUdpHeader(response));
          }
          return proxy.removeUdpHeader(response);
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

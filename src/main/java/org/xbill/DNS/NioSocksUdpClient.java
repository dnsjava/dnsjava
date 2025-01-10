// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.UdpIoClient;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
final class NioSocksUdpClient extends NioClient implements UdpIoClient {
  private static final NioTcpHandler tcpHandler = new NioTcpHandler();
  private static final NioUdpHandler udpHandler = new NioUdpHandler();
  private final Socks5ProxyConfig socksConfig;
  private static final Map<String, DatagramChannel> channelMap = new ConcurrentHashMap<>();

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
    NioTcpHandler.ChannelState tcpChannel = tcpHandler.createOrGetChannelState(local, remote, proxy, f);

    synchronized (tcpChannel) {
      if (tcpChannel.socks5HandshakeF == null) {
        tcpChannel.setSocks5(true);
        tcpChannel.socks5HandshakeF = proxy.doSocks5Handshake(tcpChannel, NioSocksHandler.SOCKS5_CMD_UDP_ASSOCIATE, query, endTime);
      }
      tcpChannel.socks5HandshakeF.thenComposeAsync(
        cmdBytes -> {
          NioSocksHandler.CmdResponse cmd = new NioSocksHandler.CmdResponse(cmdBytes);
          // newRemote is the UDP associate address
          InetSocketAddress newRemote = new InetSocketAddress(socksConfig.getProxyAddress().getAddress(), cmd.getPort());
          byte[] wrappedData = proxy.addUdpHeader(data, newRemote);
          DatagramChannel udpChannel = channelMap.computeIfAbsent(newRemote.toString(), k -> {
            try {
              return udpHandler.createChannel(local, newRemote, f);
            } catch (Exception e) {
              log.error("Failed to open UDP socket", e);
              return null;
            }
          });
          udpHandler.sendAndReceiveUdp(local, newRemote, udpChannel, query, wrappedData, max, timeout).thenApplyAsync(
            response -> {
              if (response.length < 10) {
                channelMap.remove(newRemote.toString());
                f.completeExceptionally(new IllegalStateException("SOCKS5 UDP response too short"));
              } else {
                // remove the SOCKS5 header from UDP response
                f.complete(proxy.removeUdpHeader(response));
              }
              return null;
            }
          ).exceptionally(ex -> {
            channelMap.remove(newRemote.toString());
            f.completeExceptionally(ex);
            return null;
          });
          return CompletableFuture.completedFuture(null);
        }
      ).exceptionally(ex -> {
        f.completeExceptionally(ex);
        return null;
      });
      return f;
    }
  }
}

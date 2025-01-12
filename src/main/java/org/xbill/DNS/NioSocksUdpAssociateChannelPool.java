package org.xbill.DNS;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class NioSocksUdpAssociateChannelPool {
  private final NioTcpHandler tcpHandler;
  private final NioUdpHandler udpHandler;
  private final Map<String, SocksUdpAssociateChannelGroup> channelMap = new ConcurrentHashMap<>();

  public NioSocksUdpAssociateChannelPool(NioTcpHandler tcpHandler, NioUdpHandler udpHandler) {
    this.tcpHandler = tcpHandler;
    this.udpHandler = udpHandler;
  }

  public SocksUdpAssociateChannelState createOrGetChannelState(
    InetSocketAddress local,
    InetSocketAddress remote,
    NioSocksHandler proxy,
    CompletableFuture<byte[]> future) {
    String key = local + " " + remote;
    SocksUdpAssociateChannelGroup group = channelMap.computeIfAbsent(key,
      k -> new SocksUdpAssociateChannelGroup(tcpHandler, udpHandler));
    return group.createOrGetDatagramChannel(local, remote, proxy, future);
  }

  private static class SocksUdpAssociateChannelGroup {
    private final List<SocksUdpAssociateChannelState> channels;
    private final NioTcpHandler tcpHandler;
    private final NioUdpHandler udpHandler;
    private final int defaultChannelIdleTimeout = 60000;

    public SocksUdpAssociateChannelGroup(NioTcpHandler tcpHandler, NioUdpHandler udpHandler) {
      channels = new ArrayList<>();
      this.tcpHandler = tcpHandler;
      this.udpHandler = udpHandler;
    }

    public synchronized SocksUdpAssociateChannelState createOrGetDatagramChannel(
      InetSocketAddress local,
      InetSocketAddress remote,
      NioSocksHandler proxy,
      CompletableFuture<byte[]> future) {
      SocksUdpAssociateChannelState channelState = channels.stream()
        .filter(c -> !c.isOccupied)
        .findFirst()
        .orElseGet(() -> {
          try {
            SocksUdpAssociateChannelState newChannel = new SocksUdpAssociateChannelState();
            newChannel.tcpChannel = tcpHandler.createChannelState(local, remote, proxy, future);
            newChannel.udpChannel = udpHandler.createChannel(local, future);
            newChannel.poolChannelIdleTimeout = System.currentTimeMillis() + defaultChannelIdleTimeout;
            channels.add(newChannel);
            return newChannel;
          } catch (IOException e) {
            future.completeExceptionally(e);
            return null;
          }
        });

      if (channelState != null) {
        channelState.isOccupied = true;
        return channelState;
      } else {
        return null;
      }
    }
  }

  @RequiredArgsConstructor
  @Getter
  @Setter
  public static class SocksUdpAssociateChannelState {
    private NioTcpHandler.ChannelState tcpChannel;
    private DatagramChannel udpChannel;
    private boolean isOccupied = false;
    private boolean isSocks5Initialized = false;
    private long poolChannelIdleTimeout;
  }
}

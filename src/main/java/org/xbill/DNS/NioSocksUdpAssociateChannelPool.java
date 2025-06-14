// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NioSocksUdpAssociateChannelPool {
  private final NioTcpHandler tcpHandler;
  private final NioUdpHandler udpHandler;
  private static final Map<String, SocksUdpAssociateChannelGroup> channelMap =
      new ConcurrentHashMap<>();

  public NioSocksUdpAssociateChannelPool(NioTcpHandler tcpHandler, NioUdpHandler udpHandler) {
    this.tcpHandler = tcpHandler;
    this.udpHandler = udpHandler;
  }

  public SocksUdpAssociateChannelState createOrGetSocketChannelState(
      InetSocketAddress local, InetSocketAddress remote, CompletableFuture<byte[]> future) {
    String key = local + " " + remote;
    SocksUdpAssociateChannelGroup group =
        channelMap.computeIfAbsent(
            key, k -> new SocksUdpAssociateChannelGroup(tcpHandler, udpHandler));
    return group.createOrGetDatagramChannel(local, remote, future);
  }

  public void removeIdleChannels() {
    long currentTime = System.currentTimeMillis();
    channelMap
        .values()
        .forEach(
            group -> {
              for (SocksUdpAssociateChannelState channel : group.channels) {
                if (channel.poolChannelIdleTimeout < currentTime) {
                  try {
                    group.removeChannelState(channel);
                  } catch (IOException e) {
                    log.warn("Error closing idle channel", e);
                  }
                }
              }
            });
  }

  private static class SocksUdpAssociateChannelGroup {
    private final Queue<SocksUdpAssociateChannelState> channels;
    private final NioTcpHandler tcpHandler;
    private final NioUdpHandler udpHandler;
    private final int defaultChannelIdleTimeout = 60000;

    public SocksUdpAssociateChannelGroup(NioTcpHandler tcpHandler, NioUdpHandler udpHandler) {
      channels = new ConcurrentLinkedQueue<>();
      this.tcpHandler = tcpHandler;
      this.udpHandler = udpHandler;
    }

    public SocksUdpAssociateChannelState createOrGetDatagramChannel(
        InetSocketAddress local, InetSocketAddress remote, CompletableFuture<byte[]> future) {
      SocksUdpAssociateChannelState channelState = null;
      for (Iterator<SocksUdpAssociateChannelState> it = channels.iterator(); it.hasNext(); ) {
        SocksUdpAssociateChannelState c = it.next();
        synchronized (c) {
          if (!c.isOccupied && !c.isFailed()) {
            channelState = c;
            c.occupy();
            break;
          }
        }
      }

      if (channelState == null) {
        try {
          SocksUdpAssociateChannelState newChannel = new SocksUdpAssociateChannelState();
          newChannel.tcpChannel = tcpHandler.createChannelState(local, remote, future);
          newChannel.udpChannel = udpHandler.createChannel(local, future);
          newChannel.poolChannelIdleTimeout =
              System.currentTimeMillis() + defaultChannelIdleTimeout;
          newChannel.isOccupied = true;
          channels.add(newChannel);
          channelState = newChannel;
        } catch (IOException e) {
          future.completeExceptionally(e);
        }
      }

      return channelState;
    }

    public void removeChannelState(SocksUdpAssociateChannelState channel) throws IOException {
      if (channel.occupy() || channel.isFailed()) {
        channels.remove(channel);
        channel.tcpChannel.close();
        channel.udpChannel.close();
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
    private boolean isFailed = false;
    private long poolChannelIdleTimeout;

    public synchronized boolean occupy() {
      if (!isOccupied) {
        isOccupied = true;
        return true;
      } else {
        return false;
      }
    }
  }
}

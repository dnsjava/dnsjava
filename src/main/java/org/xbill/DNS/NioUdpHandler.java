// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@Slf4j
final class NioUdpHandler extends NioClient {
  private final int ephemeralStart;
  private final int ephemeralRange;
  private final SecureRandom prng;
  private static final Queue<Transaction> registrationQueue = new ConcurrentLinkedQueue<>();
  private static final Queue<Transaction> pendingTransactions = new ConcurrentLinkedQueue<>();

  NioUdpHandler() {
    int ephemeralStartDefault = 49152;
    int ephemeralEndDefault = 65535;

    if (System.getProperty("os.name").toLowerCase().contains("linux")) {
      ephemeralStartDefault = 32768;
      ephemeralEndDefault = 60999;
    }

    ephemeralStart = Integer.getInteger("dnsjava.udp.ephemeral.start", ephemeralStartDefault);
    int ephemeralEnd = Integer.getInteger("dnsjava.udp.ephemeral.end", ephemeralEndDefault);
    ephemeralRange = ephemeralEnd - ephemeralStart;

    if (Boolean.getBoolean("dnsjava.udp.ephemeral.use_ephemeral_port")) {
      prng = null;
    } else {
      prng = new SecureRandom();
    }
    setRegistrationsTask(this::processPendingRegistrations, false);
    setTimeoutTask(this::checkTransactionTimeouts, false);
    setCloseTask(this::closeUdp, false);
  }

  private void processPendingRegistrations() {
    while (!registrationQueue.isEmpty()) {
      Transaction t = registrationQueue.poll();
      if (t == null) {
        continue;
      }

      try {
        log.trace("Registering OP_READ for transaction with id {}", t.id);
        t.channel.register(selector(), SelectionKey.OP_READ, t);
        t.send();
      } catch (IOException e) {
        t.completeExceptionally(e);
      }
    }
  }

  private void checkTransactionTimeouts() {
    for (Iterator<Transaction> it = pendingTransactions.iterator(); it.hasNext(); ) {
      Transaction t = it.next();
      if (t.endTime - System.nanoTime() < 0) {
        t.completeExceptionally(new SocketTimeoutException("Query timed out"));
        it.remove();
      }
    }
  }

  private static void silentCloseChannel(DatagramChannel channel) {
    if (channel != null) {
      try {
        channel.close();
      } catch (IOException ioe) {
        // ignore
      }
    }
  }

  private void closeUdp() {
    registrationQueue.clear();
    EOFException closing = new EOFException("Client is closing");
    pendingTransactions.forEach(t -> t.completeExceptionally(closing));
    pendingTransactions.clear();
  }

  @RequiredArgsConstructor
  private class Transaction implements KeyProcessor {
    private final int id;
    private final byte[] data;
    private final int max;
    private final long endTime;
    private final DatagramChannel channel;
    private final boolean isProxyChannel;
    private final CompletableFuture<byte[]> f;

    void send() throws IOException {
      ByteBuffer buffer = ByteBuffer.wrap(data);
      verboseLog(
          "UDP write: transaction id=" + id,
          channel.socket().getLocalSocketAddress(),
          channel.socket().getRemoteSocketAddress(),
          data);
      int n = channel.send(buffer, channel.socket().getRemoteSocketAddress());
      if (n == 0) {
        throw new EOFException(
            "Insufficient room for the datagram in the underlying output buffer for transaction "
                + id);
      } else if (n < data.length) {
        throw new EOFException("Could not send all data for transaction " + id);
      }
    }

    @Override
    public void processReadyKey(SelectionKey key) {
      if (!key.isReadable()) {
        completeExceptionally(new EOFException("Key for transaction " + id + " is not readable"));
        pendingTransactions.remove(this);
        return;
      }

      DatagramChannel keyChannel = (DatagramChannel) key.channel();
      ByteBuffer buffer = ByteBuffer.allocate(max);
      int read;
      try {
        read = keyChannel.read(buffer);
        if (read <= 0) {
          throw new EOFException();
        }
      } catch (IOException e) {
        completeExceptionally(e);
        pendingTransactions.remove(this);
        return;
      }

      buffer.flip();
      byte[] resultingData = new byte[read];
      System.arraycopy(buffer.array(), 0, resultingData, 0, read);
      verboseLog(
          "UDP read: transaction id=" + id,
          keyChannel.socket().getLocalSocketAddress(),
          keyChannel.socket().getRemoteSocketAddress(),
          resultingData);
      // do not close the channel in case of SOCKS5 UDP associate.
      // the channel port needs to be claimed for further queries to the same remote host.
      // you can not use the same UDP associate port with another local port after the first query.
      // you can also close this channel and open a new one with the same local port for further queries,
      // but I would like to avoid, that the local port will be taken by another process between queries.
      if (!isProxyChannel) {
        silentDisconnectAndCloseChannel();
      }
      f.complete(resultingData);
      pendingTransactions.remove(this);
    }

    private void completeExceptionally(Exception e) {
      silentDisconnectAndCloseChannel();
      f.completeExceptionally(e);
    }

    private void silentDisconnectAndCloseChannel() {
      try {
        channel.disconnect();
      } catch (IOException e) {
        // ignore, we either already have everything we need or can't do anything
      } finally {
        NioUdpHandler.silentCloseChannel(channel);
      }
    }
  }


  public DatagramChannel createChannel(InetSocketAddress local, CompletableFuture<byte[]> f) throws IOException {
    DatagramChannel channel = DatagramChannel.open();
    channel.configureBlocking(false);
    if (local == null || local.getPort() == 0) {
      boolean bound = false;
        for (int i = 0; i < 1024; i++) {
          try {
            InetSocketAddress addr = null;
            if (local == null) {
              if (prng != null) {
                addr = new InetSocketAddress(prng.nextInt(ephemeralRange) + ephemeralStart);
              }
            } else {
              int port = local.getPort();
              if (port == 0 && prng != null) {
                port = prng.nextInt(ephemeralRange) + ephemeralStart;
              }

              addr = new InetSocketAddress(local.getAddress(), port);
            }

            channel.bind(addr);
            bound = true;
            break;
          } catch (SocketException e) {
            // ignore, we'll try another random port
          }
        }
      if (!bound) {
        f.completeExceptionally(new IOException("No available source port found"));
        return null;
      }
    } else {
      channel.bind(local);
    }
    return channel;
  }

  public CompletableFuture<byte[]> sendAndReceiveUdp(
      InetSocketAddress local,
      InetSocketAddress remote,
      DatagramChannel channel,
      Message query,
      byte[] data,
      int max,
      Duration timeout) {
    long endTime = System.nanoTime() + timeout.toNanos();
    CompletableFuture<byte[]> f = new CompletableFuture<>();

    try {
      boolean isProxyChannel = (channel != null);
      if (channel == null) {
        channel = createChannel(local, f);
      }
      if (channel != null) {
        if (!channel.isConnected()) {
          channel.connect(remote);
        }
      } else {
        f.completeExceptionally(new IOException("Could not create channel"));
        return f;
      }

      Transaction t = new Transaction(query.getHeader().getID(), data, max, endTime, channel, isProxyChannel, f);

      final Selector selector = selector();
      pendingTransactions.add(t);
      registrationQueue.add(t);
      selector.wakeup();
    } catch (IOException e) {
      silentCloseChannel(channel);
      f.completeExceptionally(e);
    } catch (Throwable e) {
      silentCloseChannel(channel);
      throw e;
    }

    return f;
  }
}

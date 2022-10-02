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
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
final class NioUdpClient extends NioClient {
  private static final int EPHEMERAL_START;
  private static final int EPHEMERAL_RANGE;

  private static final SecureRandom prng;
  private static final Queue<Transaction> registrationQueue = new ConcurrentLinkedQueue<>();
  private static final Queue<Transaction> pendingTransactions = new ConcurrentLinkedQueue<>();

  static {
    // https://tools.ietf.org/html/rfc6335#section-6
    int ephemeralStartDefault = 49152;
    int ephemeralEndDefault = 65535;

    // Linux usually uses 32768-60999
    if (System.getProperty("os.name").toLowerCase().contains("linux")) {
      ephemeralStartDefault = 32768;
      ephemeralEndDefault = 60999;
    }

    EPHEMERAL_START = Integer.getInteger("dnsjava.udp.ephemeral.start", ephemeralStartDefault);
    int ephemeralEnd = Integer.getInteger("dnsjava.udp.ephemeral.end", ephemeralEndDefault);
    EPHEMERAL_RANGE = ephemeralEnd - EPHEMERAL_START;

    if (Boolean.getBoolean("dnsjava.udp.ephemeral.use_ephemeral_port")) {
      prng = null;
    } else {
      prng = new SecureRandom();
    }
    setRegistrationsTask(NioUdpClient::processPendingRegistrations);
    setTimeoutTask(NioUdpClient::checkTransactionTimeouts);
    setCloseTask(NioUdpClient::closeUdp);
  }

  private static void processPendingRegistrations() {
    while (!registrationQueue.isEmpty()) {
      Transaction t = registrationQueue.remove();
      try {
        t.channel.register(selector(), SelectionKey.OP_READ, t);
        t.send();
      } catch (IOException e) {
        t.f.completeExceptionally(e);
      }
    }
  }

  private static void checkTransactionTimeouts() {
    for (Iterator<Transaction> it = pendingTransactions.iterator(); it.hasNext(); ) {
      Transaction t = it.next();
      if (t.endTime - System.nanoTime() < 0) {
        t.silentCloseChannel();
        t.f.completeExceptionally(new SocketTimeoutException("Query timed out"));
        it.remove();
      }
    }
  }

  @RequiredArgsConstructor
  private static class Transaction implements KeyProcessor {
    private final byte[] data;
    private final int max;
    private final long endTime;
    private final DatagramChannel channel;
    private final CompletableFuture<byte[]> f;

    void send() throws IOException {
      ByteBuffer buffer = ByteBuffer.wrap(data);
      verboseLog(
          "UDP write",
          channel.socket().getLocalSocketAddress(),
          channel.socket().getRemoteSocketAddress(),
          data);
      int n = channel.send(buffer, channel.socket().getRemoteSocketAddress());
      if (n <= 0) {
        throw new EOFException();
      }
    }

    @Override
    public void processReadyKey(SelectionKey key) {
      if (!key.isReadable()) {
        silentCloseChannel();
        f.completeExceptionally(new EOFException("channel not readable"));
        pendingTransactions.remove(this);
        return;
      }

      DatagramChannel channel = (DatagramChannel) key.channel();
      ByteBuffer buffer = ByteBuffer.allocate(max);
      int read;
      try {
        read = channel.read(buffer);
        if (read <= 0) {
          throw new EOFException();
        }
      } catch (IOException e) {
        silentCloseChannel();
        f.completeExceptionally(e);
        pendingTransactions.remove(this);
        return;
      }

      buffer.flip();
      byte[] data = new byte[read];
      System.arraycopy(buffer.array(), 0, data, 0, read);
      verboseLog(
          "UDP read",
          channel.socket().getLocalSocketAddress(),
          channel.socket().getRemoteSocketAddress(),
          data);
      silentCloseChannel();
      f.complete(data);
      pendingTransactions.remove(this);
    }

    private void silentCloseChannel() {
      try {
        channel.disconnect();
      } catch (IOException e) {
        // ignore, we either already have everything we need or can't do anything
      } finally {
        try {
          channel.close();
        } catch (IOException e) {
          // ignore
        }
      }
    }
  }

  static CompletableFuture<byte[]> sendrecv(
      InetSocketAddress local, InetSocketAddress remote, byte[] data, int max, Duration timeout) {
    CompletableFuture<byte[]> f = new CompletableFuture<>();
    try {
      final Selector selector = selector();
      DatagramChannel channel = DatagramChannel.open();
      channel.configureBlocking(false);
      if (local == null || local.getPort() == 0) {
        boolean bound = false;
        for (int i = 0; i < 1024; i++) {
          try {
            InetSocketAddress addr = null;
            if (local == null) {
              if (prng != null) {
                addr = new InetSocketAddress(prng.nextInt(EPHEMERAL_RANGE) + EPHEMERAL_START);
              }
            } else {
              int port = local.getPort();
              if (port == 0 && prng != null) {
                port = prng.nextInt(EPHEMERAL_RANGE) + EPHEMERAL_START;
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
          channel.close();
          f.completeExceptionally(new IOException("No available source port found"));
          return f;
        }
      }

      channel.connect(remote);
      long endTime = System.nanoTime() + timeout.toNanos();
      Transaction t = new Transaction(data, max, endTime, channel, f);
      pendingTransactions.add(t);
      registrationQueue.add(t);
      selector.wakeup();
    } catch (IOException e) {
      f.completeExceptionally(e);
    }

    return f;
  }

  private static void closeUdp() {
    registrationQueue.clear();
    EOFException closing = new EOFException("Client is closing");
    pendingTransactions.forEach(t -> t.f.completeExceptionally(closing));
    pendingTransactions.clear();
  }
}

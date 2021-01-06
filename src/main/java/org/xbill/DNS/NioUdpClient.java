// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
final class NioUdpClient extends Client {
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
    addSelectorTimeoutTask(NioUdpClient::processPendingRegistrations);
    addSelectorTimeoutTask(NioUdpClient::checkTransactionTimeouts);
    addCloseTask(NioUdpClient::closeUdp);
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
        t.closeTransaction();
        it.remove();
      }
    }
  }

  @RequiredArgsConstructor
  private static class Transaction implements KeyProcessor {
    private final byte[] data;
    final int max;
    private final long endTime;
    private final DatagramChannel channel;
    private final SocketAddress remoteSocketAddress;
    final CompletableFuture<Object> f;

    void send() throws IOException {
      ByteBuffer buffer = ByteBuffer.wrap(data);
      verboseLog(
          "UDP write",
          channel.socket().getLocalSocketAddress(),
          remoteSocketAddress,
          data);
      int n = channel.send(buffer, remoteSocketAddress);
      if (n <= 0) {
        throw new EOFException();
      }
    }

    public void processReadyKey(SelectionKey key) {
      if (!key.isReadable()) {
        silentCloseChannel();
        f.completeExceptionally(new EOFException("channel not readable"));
        pendingTransactions.remove(this);
        return;
      }

      DatagramChannel channel = (DatagramChannel) key.channel();
      ByteBuffer buffer = ByteBuffer.allocate(max);
      SocketAddress source;
      int read;
      try {
        source = channel.receive(buffer);
        read = buffer.position();
        if (read <= 0 || source == null) {
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
          remoteSocketAddress,
          data);
      silentCloseChannel();
      f.complete(data);
      pendingTransactions.remove(this);
    }

    void silentCloseChannel() {
      try {
        channel.disconnect();
        channel.close();
      } catch (IOException e) {
        // ignore, we either already have everything we need or can't do anything
      }
    }
    
    void closeTransaction() {
      silentCloseChannel();
      f.completeExceptionally(new SocketTimeoutException("Query timed out"));
    }
  }

  private static class MultiAnswerTransaction extends Transaction {
      MultiAnswerTransaction(byte[] query, int max, long endTime, DatagramChannel channel,
                           SocketAddress remoteSocketAddress,
                           CompletableFuture<Object> f) {
        super(query, max, endTime, channel, remoteSocketAddress, f);
      }

      public void processReadyKey(SelectionKey key) {
      if (!key.isReadable()) {
        silentCloseChannel();
        f.completeExceptionally(new EOFException("channel not readable"));
        pendingTransactions.remove(this);
        return;
      }

      DatagramChannel channel = (DatagramChannel) key.channel();
      ByteBuffer buffer = ByteBuffer.allocate(max);
      SocketAddress source;
      int read;
      try {
        source = channel.receive(buffer);
        read = buffer.position();
        if (read <= 0 || source == null) {
          return; // ignore this datagram
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
        source,
        data);
      answers.add(data);
    }

    private ArrayList<byte[]> answers = new ArrayList<>();

    @Override
    void closeTransaction() {
      if (answers.size() > 0) {
        silentCloseChannel();
        f.complete(answers);
      } else {
        // we failed, no answers
        super.closeTransaction();
      }
    }
  }

  static CompletableFuture<Object> sendrecv(
      InetSocketAddress local, InetSocketAddress remote, byte[] data, int max, Duration timeout) {
    CompletableFuture<Object> f = new CompletableFuture<>();
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

      long endTime = System.nanoTime() + timeout.toNanos();
      Transaction t;
      if (!remote.getAddress().isMulticastAddress()) {
        channel.connect(remote);
        t = new Transaction(data, max, endTime, channel, f);
      } else {
        // stop this a little before the timeout so we can report what answers we did get
        t = new MultiAnswerTransaction(data, max, endTime - 1000000000L, channel, f);
      }
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

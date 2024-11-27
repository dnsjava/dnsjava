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
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.io.UdpIoClient;

@Slf4j
final class NioUdpClient extends NioClient implements UdpIoClient {
  private final int ephemeralStart;
  private final int ephemeralRange;

  private final SecureRandom prng;
  private final Queue<Transaction> registrationQueue = new ConcurrentLinkedQueue<>();
  private final Queue<Transaction> pendingTransactions = new ConcurrentLinkedQueue<>();

  NioUdpClient() {
    // https://datatracker.ietf.org/doc/html/rfc6335#section-6
    int ephemeralStartDefault = 49152;
    int ephemeralEndDefault = 65535;

    // Linux usually uses 32768-60999
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
        t.udpChannel.register(selector(), SelectionKey.OP_READ, t);
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

  @RequiredArgsConstructor
  private class Transaction implements KeyProcessor {
    private final int id;
    private final byte[] data;
    private final int max;
    private final long endTime;
    private final DatagramChannel udpChannel;
    private final SocketChannel tcpChannel;
    private final Socks5Proxy proxy;
    private final CompletableFuture<byte[]> f;

    void send() throws IOException {
      ByteBuffer buffer = ByteBuffer.wrap(data);
      verboseLog(
          "UDP write: transaction id=" + id,
          udpChannel.socket().getLocalSocketAddress(),
          udpChannel.socket().getRemoteSocketAddress(),
          data);
      int n = udpChannel.send(buffer, udpChannel.socket().getRemoteSocketAddress());
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
      silentDisconnectAndCloseChannel();
      if (proxy != null && tcpChannel != null) {
        resultingData = proxy.removeUdpHeader(resultingData);
        try {
          tcpChannel.close();
        } catch (IOException e) {
          // ignore, we either already have everything we need or can't do anything
        }
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
        udpChannel.disconnect();
      } catch (IOException e) {
        // ignore, we either already have everything we need or can't do anything
      } finally {
        NioUdpClient.silentCloseChannel(udpChannel);
      }
    }
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveUdp(
    InetSocketAddress local,
    InetSocketAddress remote,
    Message query,
    byte[] data,
    int max,
    Duration timeout) {
    return sendAndReceiveUdp(local, remote, null, query, data, max, timeout);
  }

  @Override
  public CompletableFuture<byte[]> sendAndReceiveUdp(
      InetSocketAddress local,
      InetSocketAddress remote,
      Socks5Proxy proxy,
      Message query,
      byte[] data,
      int max,
      Duration timeout) {
    long endTime = System.nanoTime() + timeout.toNanos();
    CompletableFuture<byte[]> f = new CompletableFuture<>();
    DatagramChannel udpChannel = null;
    SocketChannel tcpChannel = null;
    try {
      final Selector selector = selector();

      // SOCKS5 handshake to set up the UDP association
      if (proxy != null) {
        data = proxy.addUdpHeader(data, remote);
        try {
          tcpChannel = SocketChannel.open();
          if (local != null) {
            tcpChannel.bind(local);
          }
          tcpChannel.connect(proxy.getProxyAddress());
          remote = proxy.socks5UdpAssociateHandshake(tcpChannel);
        } catch (IOException e) {
          return new CompletableFuture<>().thenComposeAsync(in -> {
            f.completeExceptionally(new WireParseException("Error in Udp Associate SOCKS5 handshake", e));
            return f;
          });
        }
      }

      udpChannel = DatagramChannel.open();
      udpChannel.configureBlocking(false);

      Transaction t = new Transaction(query.getHeader().getID(), data, max, endTime, udpChannel, tcpChannel, proxy, f);
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

            udpChannel.bind(addr);
            bound = true;
            break;
          } catch (SocketException e) {
            // ignore, we'll try another random port
          }
        }

        if (!bound) {
          t.completeExceptionally(new IOException("No available source port found"));
          return f;
        }
      }

      udpChannel.connect(remote);
      pendingTransactions.add(t);
      registrationQueue.add(t);
      selector.wakeup();
    } catch (IOException e) {
      silentCloseChannel(udpChannel);
      f.completeExceptionally(e);
    } catch (Throwable e) {
      // Make sure to close the channel, no matter what, but only handle the declared IOException
      silentCloseChannel(udpChannel);
      throw e;
    }

    return f;
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
}

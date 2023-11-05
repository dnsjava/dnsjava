// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
final class NioTcpClient extends NioClient {
  private static final Queue<ChannelState> registrationQueue = new ConcurrentLinkedQueue<>();
  private static final Map<ChannelKey, ChannelState> channelMap = new ConcurrentHashMap<>();

  static {
    setRegistrationsTask(NioTcpClient::processPendingRegistrations, true);
    setTimeoutTask(NioTcpClient::checkTransactionTimeouts, true);
    setCloseTask(NioTcpClient::closeTcp, true);
  }

  private static void processPendingRegistrations() {
    while (!registrationQueue.isEmpty()) {
      ChannelState state = registrationQueue.remove();
      try {
        final Selector selector = selector();
        if (!state.channel.isConnected()) {
          state.channel.register(selector, SelectionKey.OP_CONNECT, state);
        } else {
          state.channel.keyFor(selector).interestOps(SelectionKey.OP_WRITE);
        }
      } catch (IOException e) {
        state.handleChannelException(e);
      }
    }
  }

  private static void checkTransactionTimeouts() {
    for (ChannelState state : channelMap.values()) {
      for (Iterator<Transaction> it = state.pendingTransactions.iterator(); it.hasNext(); ) {
        Transaction t = it.next();
        if (t.endTime - System.nanoTime() < 0) {
          t.f.completeExceptionally(new SocketTimeoutException("Query timed out"));
          it.remove();
        }
      }
    }
  }

  private static void closeTcp() {
    registrationQueue.clear();
    EOFException closing = new EOFException("Client is closing");
    channelMap.forEach((key, state) -> state.handleTransactionException(closing));
    channelMap.clear();
  }

  @RequiredArgsConstructor
  private static class Transaction {
    private final Message query;
    private final byte[] queryData;
    private final long endTime;
    private final SocketChannel channel;
    private final CompletableFuture<byte[]> f;
    private boolean sendDone;

    void send() throws IOException {
      if (sendDone) {
        return;
      }

      verboseLog(
          "TCP write: transaction id=" + query.getHeader().getID(),
          channel.socket().getLocalSocketAddress(),
          channel.socket().getRemoteSocketAddress(),
          queryData);

      // combine length+message to avoid multiple TCP packets
      // https://tools.ietf.org/html/rfc7766#section-8
      ByteBuffer buffer = ByteBuffer.allocate(queryData.length + 2);
      buffer.put((byte) (queryData.length >>> 8));
      buffer.put((byte) (queryData.length & 0xFF));
      buffer.put(queryData);
      buffer.flip();
      while (buffer.hasRemaining()) {
        long n = channel.write(buffer);
        if (n == 0) {
          throw new EOFException(
              "Insufficient room for the data in the underlying output buffer for transaction "
                  + query.getHeader().getID());
        } else if (n < queryData.length) {
          throw new EOFException(
              "Could not write all data for transaction " + query.getHeader().getID());
        }
      }

      sendDone = true;
    }
  }

  @RequiredArgsConstructor
  private static class ChannelState implements KeyProcessor {
    final SocketChannel channel;
    final Queue<Transaction> pendingTransactions = new ConcurrentLinkedQueue<>();
    ByteBuffer responseLengthData = ByteBuffer.allocate(2);
    ByteBuffer responseData = ByteBuffer.allocate(Message.MAXLENGTH);
    int readState = 0;

    @Override
    public void processReadyKey(SelectionKey key) {
      if (key.isValid()) {
        if (key.isConnectable()) {
          processConnect(key);
        } else {
          if (key.isWritable()) {
            processWrite(key);
          }
          if (key.isReadable()) {
            processRead();
          }
        }
      }
    }

    void handleTransactionException(IOException e) {
      for (Iterator<Transaction> it = pendingTransactions.iterator(); it.hasNext(); ) {
        Transaction t = it.next();
        t.f.completeExceptionally(e);
        it.remove();
      }
    }

    private void handleChannelException(IOException e) {
      handleTransactionException(e);
      for (Map.Entry<ChannelKey, ChannelState> entry : channelMap.entrySet()) {
        if (entry.getValue() == this) {
          channelMap.remove(entry.getKey());
          try {
            channel.close();
          } catch (IOException ex) {
            log.warn(
                "Failed to close channel l={}/r={}",
                entry.getKey().local,
                entry.getKey().remote,
                ex);
          }
          return;
        }
      }
    }

    private void processConnect(SelectionKey key) {
      try {
        channel.finishConnect();
        key.interestOps(SelectionKey.OP_WRITE);
      } catch (IOException e) {
        handleChannelException(e);
      }
    }

    private void processRead() {
      try {
        if (readState == 0) {
          int read = channel.read(responseLengthData);
          if (read < 0) {
            handleChannelException(new EOFException());
            return;
          }

          if (responseLengthData.position() == 2) {
            int length =
                ((responseLengthData.get(0) & 0xFF) << 8) + (responseLengthData.get(1) & 0xFF);
            responseLengthData.flip();
            responseData.limit(length);
            readState = 1;
          }
        }

        int read = channel.read(responseData);
        if (read < 0) {
          handleChannelException(new EOFException());
          return;
        } else if (responseData.hasRemaining()) {
          return;
        }
      } catch (IOException e) {
        handleChannelException(e);
        return;
      }

      readState = 0;
      responseData.flip();
      byte[] data = new byte[responseData.limit()];
      System.arraycopy(
          responseData.array(), responseData.arrayOffset(), data, 0, responseData.limit());

      // The message was shorter than the minimum length to find the transaction, abort
      if (data.length < 2) {
        verboseLog(
            "TCP read: response too short for a valid reply, discarding",
            channel.socket().getLocalSocketAddress(),
            channel.socket().getRemoteSocketAddress(),
            data);
        return;
      }

      int id = ((data[0] & 0xFF) << 8) + (data[1] & 0xFF);
      verboseLog(
          "TCP read: transaction id=" + id,
          channel.socket().getLocalSocketAddress(),
          channel.socket().getRemoteSocketAddress(),
          data);

      for (Iterator<Transaction> it = pendingTransactions.iterator(); it.hasNext(); ) {
        Transaction t = it.next();
        int qid = t.query.getHeader().getID();
        if (id == qid) {
          t.f.complete(data);
          it.remove();
          return;
        }
      }

      log.warn("Transaction for answer to id {} not found", id);
    }

    private void processWrite(SelectionKey key) {
      for (Iterator<Transaction> it = pendingTransactions.iterator(); it.hasNext(); ) {
        Transaction t = it.next();
        try {
          t.send();
        } catch (IOException e) {
          t.f.completeExceptionally(e);
          it.remove();
        }
      }

      key.interestOps(SelectionKey.OP_READ);
    }
  }

  @RequiredArgsConstructor
  @EqualsAndHashCode
  private static class ChannelKey {
    final InetSocketAddress local;
    final InetSocketAddress remote;
  }

  static CompletableFuture<byte[]> sendrecv(
      InetSocketAddress local,
      InetSocketAddress remote,
      Message query,
      byte[] data,
      Duration timeout) {
    CompletableFuture<byte[]> f = new CompletableFuture<>();
    try {
      final Selector selector = selector();
      long endTime = System.nanoTime() + timeout.toNanos();
      ChannelState channel =
          channelMap.computeIfAbsent(
              new ChannelKey(local, remote),
              key -> {
                log.debug("Opening async channel for l={}/r={}", local, remote);
                SocketChannel c = null;
                try {
                  c = SocketChannel.open();
                  c.configureBlocking(false);
                  if (local != null) {
                    c.bind(local);
                  }

                  c.connect(remote);
                  return new ChannelState(c);
                } catch (IOException e) {
                  if (c != null) {
                    try {
                      c.close();
                    } catch (IOException ee) {
                      // ignore
                    }
                  }
                  f.completeExceptionally(e);
                  return null;
                }
              });
      if (channel != null) {
        log.trace(
            "Creating transaction for id {} ({}/{})",
            query.getHeader().getID(),
            query.getQuestion().getName(),
            Type.string(query.getQuestion().getType()));
        Transaction t = new Transaction(query, data, endTime, channel.channel, f);
        channel.pendingTransactions.add(t);
        registrationQueue.add(channel);
        selector.wakeup();
      }
    } catch (IOException e) {
      f.completeExceptionally(e);
    }

    return f;
  }
}

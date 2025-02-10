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
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
public class NioTcpHandler extends NioClient {
  // `registrationQueue` and `channelMap` must be static to be shared between instances.
  // This is necessary because a second instance overwrites the registration, timeout, and close
  // tasks,
  // leaving no thread to process the pending registrations for the first instance.
  private static final Queue<ChannelState> registrationQueue = new ConcurrentLinkedQueue<>();
  private static final Map<ChannelKey, ChannelState> channelMap = new ConcurrentHashMap<>();

  NioTcpHandler() {
    setRegistrationsTask(this::processPendingRegistrations, true);
    setTimeoutTask(this::checkTransactionTimeouts, true);
    setCloseTask(this::closeTcp, true);
  }

  private void processPendingRegistrations() {
    while (!registrationQueue.isEmpty()) {
      ChannelState state = registrationQueue.poll();
      if (state == null) {
        continue;
      }

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

  private void checkTransactionTimeouts() {
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

  private void closeTcp() {
    registrationQueue.clear();
    EOFException closing = new EOFException("Client is closing");
    channelMap.forEach(
        (key, state) -> {
          state.handleTransactionException(closing);
          state.handleChannelException(closing);
        });
    channelMap.clear();
  }

  @RequiredArgsConstructor
  public static class Transaction {
    private final Message query;
    private final byte[] queryData;
    private final long endTime;
    private final SocketChannel channel;
    private final CompletableFuture<byte[]> f;
    private final boolean isSocks5;
    private ByteBuffer queryDataBuffer;
    long bytesWrittenTotal = 0;

    boolean send() throws IOException {
      // send can be invoked multiple times if the entire buffer couldn't be written at once
      if (bytesWrittenTotal == queryData.length + 2) {
        return true;
      }
      if (queryDataBuffer == null) {
        if (isSocks5) {
          queryDataBuffer = ByteBuffer.wrap(queryData);
        } else {
          // combine length+message to avoid multiple TCP packets
          // https://datatracker.ietf.org/doc/html/rfc7766#section-8
          queryDataBuffer = ByteBuffer.allocate(queryData.length + 2);
          queryDataBuffer.put((byte) (queryData.length >>> 8));
          queryDataBuffer.put((byte) (queryData.length & 0xFF));
          queryDataBuffer.put(queryData);
          queryDataBuffer.flip();
        }
      }

      verboseLog(
          "TCP write: transaction id=" + query.getHeader().getID(),
          channel.socket().getLocalSocketAddress(),
          channel.socket().getRemoteSocketAddress(),
          queryDataBuffer);
      while (queryDataBuffer.hasRemaining()) {
        long bytesWritten = channel.write(queryDataBuffer);
        bytesWrittenTotal += bytesWritten;
        if (bytesWritten == 0) {
          log.debug(
              "Insufficient room for the data in the underlying output buffer for transaction {}, retrying",
              query.getHeader().getID());
          return false;
        } else if (bytesWrittenTotal < queryData.length) {
          log.debug(
              "Wrote {} of {} bytes data for transaction {}",
              bytesWrittenTotal,
              queryData.length,
              query.getHeader().getID());
        }
      }

      log.debug(
          "Send for transaction {} is complete, wrote {} bytes",
          query.getHeader().getID(),
          bytesWrittenTotal);
      return true;
    }
  }

  @RequiredArgsConstructor
  @Getter
  @Setter
  public class ChannelState implements KeyProcessor {
    private final SocketChannel channel;
    final Queue<Transaction> pendingTransactions = new ConcurrentLinkedQueue<>();
    ByteBuffer responseLengthData = ByteBuffer.allocate(2);
    ByteBuffer responseData = ByteBuffer.allocate(Message.MAXLENGTH);
    int readState = 0;
    boolean isSocks5;
    CompletableFuture<byte[]> socks5HandshakeF;

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
      close();
    }

    public void close() {
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
        if (isSocks5) {
          responseData = ByteBuffer.allocate(Message.MAXLENGTH);
          int read = channel.read(responseData);
          if (read < 0) {
            handleChannelException(new EOFException());
            return;
          }
          responseData.flip();
          byte[] data = new byte[responseData.limit()];
          System.arraycopy(
              responseData.array(), responseData.arrayOffset(), data, 0, responseData.limit());
          // the transactions for the socks5 handshake are synchronized
          // you can assume that the responses are one after another
          for (Iterator<Transaction> it = pendingTransactions.iterator(); it.hasNext(); ) {
            Transaction t = it.next();
            t.f.complete(data);
            it.remove();
            return;
          }
          return;
        }

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
          if (!t.send()) {
            // Write was incomplete because the output buffer was full. Wait until the selector
            // tells us that we can write again
            key.interestOps(SelectionKey.OP_WRITE);
            return;
          }
        } catch (IOException e) {
          t.f.completeExceptionally(e);
          it.remove();
        }
      }

      key.interestOps(SelectionKey.OP_READ);
    }

    public void queueTransaction(Transaction t) {
      try {
        final Selector selector = selector();
        pendingTransactions.add(t);
        registrationQueue.add(this);
        selector.wakeup();
      } catch (IOException e) {
        t.f.completeExceptionally(e);
      }
    }
  }

  @RequiredArgsConstructor
  @EqualsAndHashCode
  static class ChannelKey {
    final InetSocketAddress local;
    final InetSocketAddress remote;
  }

  public void dnsTransaction(
      ChannelState channel, Message query, byte[] data, long endTime, CompletableFuture<byte[]> f) {
    channel.setSocks5(false);
    Transaction t = new Transaction(query, data, endTime, channel.channel, f, false);
    channel.queueTransaction(t);
  }

  public ChannelState createChannelState(
      InetSocketAddress local, InetSocketAddress remote, CompletableFuture<byte[]> f) {
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
  }

  public ChannelState createOrGetChannelState(
      InetSocketAddress local, InetSocketAddress remote, CompletableFuture<byte[]> f) {
    return channelMap.computeIfAbsent(
        new ChannelKey(local, remote), key -> createChannelState(local, remote, f));
  }

  public CompletableFuture<byte[]> sendAndReceiveTcp(
      InetSocketAddress local,
      InetSocketAddress remote,
      NioSocksHandler proxy,
      Message query,
      byte[] data,
      Duration timeout) {
    CompletableFuture<byte[]> f = new CompletableFuture<>();

    InetSocketAddress remoteAddr;
    if (proxy != null) {
      remoteAddr = proxy.getProxyAddress();
    } else {
      remoteAddr = remote;
    }
    ChannelState channel = createOrGetChannelState(local, remoteAddr, f);
    if (channel != null) {
      log.trace(
          "Creating transaction for id {} ({}/{})",
          query.getHeader().getID(),
          query.getQuestion().getName(),
          Type.string(query.getQuestion().getType()));

      long endTime = System.nanoTime() + timeout.toNanos();
      if (proxy != null) {
        synchronized (channel) {
          if (channel.socks5HandshakeF == null
              || channel.socks5HandshakeF.isCompletedExceptionally()) {
            channel.setSocks5(true);
            channel.socks5HandshakeF =
                proxy.doSocks5Handshake(
                    channel, NioSocksHandler.SOCKS5_CMD_CONNECT, query, endTime);
          }
        }
        // Chain the SOCKS5 transactions with the DNS data transaction
        channel
            .socks5HandshakeF
            .thenRunAsync(
                () -> {
                  dnsTransaction(channel, query, data, endTime, f);
                })
            .exceptionally(
                ex -> {
                  f.completeExceptionally(ex);
                  return null;
                });
      } else {
        dnsTransaction(channel, query, data, endTime, f);
      }
    }

    return f;
  }
}

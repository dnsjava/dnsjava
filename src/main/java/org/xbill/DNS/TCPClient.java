// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

class TCPClient implements AutoCloseable {
  private final long startTime;
  private final Duration timeout;
  private final SelectionKey key;

  TCPClient(Duration timeout) throws IOException {
    this.timeout = timeout;
    startTime = System.nanoTime();
    boolean done = false;
    Selector selector = null;
    SocketChannel channel = SocketChannel.open();
    try {
      selector = Selector.open();
      channel.configureBlocking(false);
      key = channel.register(selector, SelectionKey.OP_READ);
      done = true;
    } finally {
      if (!done && selector != null) {
        selector.close();
      }
      if (!done) {
        channel.close();
      }
    }
  }

  void bind(SocketAddress addr) throws IOException {
    SocketChannel channel = (SocketChannel) key.channel();
    channel.socket().bind(addr);
  }

  void connect(SocketAddress addr) throws IOException {
    SocketChannel channel = (SocketChannel) key.channel();
    if (channel.connect(addr)) {
      return;
    }
    key.interestOps(SelectionKey.OP_CONNECT);
    try {
      while (!channel.finishConnect()) {
        if (!key.isConnectable()) {
          blockUntil(key);
        }
      }
    } finally {
      if (key.isValid()) {
        key.interestOps(0);
      }
    }
  }

  void send(byte[] data) throws IOException {
    SocketChannel channel = (SocketChannel) key.channel();
    NioClient.verboseLog(
        "TCP write",
        channel.socket().getLocalSocketAddress(),
        channel.socket().getRemoteSocketAddress(),
        data);
    byte[] lengthArray = new byte[2];
    lengthArray[0] = (byte) (data.length >>> 8);
    lengthArray[1] = (byte) (data.length & 0xFF);
    ByteBuffer[] buffers = new ByteBuffer[2];
    buffers[0] = ByteBuffer.wrap(lengthArray);
    buffers[1] = ByteBuffer.wrap(data);
    int nsent = 0;
    key.interestOps(SelectionKey.OP_WRITE);
    try {
      while (nsent < data.length + 2) {
        if (key.isWritable()) {
          long n = channel.write(buffers);
          if (n < 0) {
            throw new EOFException();
          }
          nsent += (int) n;
          if (nsent < data.length + 2 && System.nanoTime() - startTime >= timeout.toNanos()) {
            throw new SocketTimeoutException();
          }
        } else {
          blockUntil(key);
        }
      }
    } finally {
      if (key.isValid()) {
        key.interestOps(0);
      }
    }
  }

  private byte[] _recv(int length) throws IOException {
    SocketChannel channel = (SocketChannel) key.channel();
    int nrecvd = 0;
    byte[] data = new byte[length];
    ByteBuffer buffer = ByteBuffer.wrap(data);
    key.interestOps(SelectionKey.OP_READ);
    try {
      while (nrecvd < length) {
        if (key.isReadable()) {
          long n = channel.read(buffer);
          if (n < 0) {
            throw new EOFException();
          }
          nrecvd += (int) n;
          if (nrecvd < length && System.nanoTime() - startTime >= timeout.toNanos()) {
            throw new SocketTimeoutException();
          }
        } else {
          blockUntil(key);
        }
      }
    } finally {
      if (key.isValid()) {
        key.interestOps(0);
      }
    }
    return data;
  }

  private void blockUntil(SelectionKey key) throws IOException {
    long remainingTimeout =
        timeout.minus(System.nanoTime() - startTime, ChronoUnit.NANOS).toMillis();
    int nkeys = 0;
    if (remainingTimeout > 0) {
      nkeys = key.selector().select(remainingTimeout);
    } else if (remainingTimeout == 0) {
      nkeys = key.selector().selectNow();
    }
    if (nkeys == 0) {
      throw new SocketTimeoutException();
    }
  }

  public void close() throws IOException {
    key.selector().close();
    key.channel().close();
  }

  byte[] recv() throws IOException {
    byte[] buf = _recv(2);
    int length = ((buf[0] & 0xFF) << 8) + (buf[1] & 0xFF);
    byte[] data = _recv(length);
    SocketChannel channel = (SocketChannel) key.channel();
    NioClient.verboseLog(
        "TCP read",
        channel.socket().getLocalSocketAddress(),
        channel.socket().getRemoteSocketAddress(),
        data);
    return data;
  }
}

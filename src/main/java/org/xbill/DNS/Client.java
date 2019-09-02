// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.hexdump;

@Slf4j
class Client {

  protected long endTime;
  protected SelectionKey key;

  /** Packet logger, if available. */
  private static PacketLogger packetLogger = null;

  protected Client(SelectableChannel channel, long endTime) throws IOException {
    boolean done = false;
    Selector selector = null;
    this.endTime = endTime;
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

  protected static void blockUntil(SelectionKey key, long endTime) throws IOException {
    long timeout = endTime - System.currentTimeMillis();
    int nkeys = 0;
    if (timeout > 0) {
      nkeys = key.selector().select(timeout);
    } else if (timeout == 0) {
      nkeys = key.selector().selectNow();
    }
    if (nkeys == 0) {
      throw new SocketTimeoutException();
    }
  }

  protected static void verboseLog(
      String prefix, SocketAddress local, SocketAddress remote, byte[] data) {
    if (log.isDebugEnabled()) {
      log.debug(hexdump.dump(prefix, data));
    }
    if (packetLogger != null) {
      packetLogger.log(prefix, local, remote, data);
    }
  }

  void cleanup() throws IOException {
    key.selector().close();
    key.channel().close();
  }

  static void setPacketLogger(PacketLogger logger) {
    packetLogger = logger;
  }
}

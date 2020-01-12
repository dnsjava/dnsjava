// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.hexdump;

@Slf4j
class Client {
  /** Packet logger, if available. */
  private static PacketLogger packetLogger = null;

  private static volatile boolean run;
  private static Thread selectorThread;
  private static List<Runnable> timeoutTasks = new CopyOnWriteArrayList<>();
  static Selector selector;

  protected interface KeyProcessor {
    void processReadyKey(SelectionKey key);
  }

  protected static void start() throws IOException {
    if (run) {
      return;
    }

    log.debug("Starting dnsjava NIO selector thread");
    run = true;
    selector = Selector.open();
    selectorThread = new Thread(Client::runSelector);
    selectorThread.setDaemon(true);
    selectorThread.setName("dnsjava NIO selector");
    selectorThread.start();
  }

  protected static void close() throws Exception {
    if (!run) {
      return;
    }

    run = false;
    timeoutTasks.clear();
    selector.wakeup();
    selector.close();
    selectorThread.join();
  }

  private static void runSelector() {
    while (run) {
      try {
        if (selector.select(1000) == 0) {
          timeoutTasks.forEach(Runnable::run);
        }

        processReadyKeys();
      } catch (IOException e) {
        log.error("A selection operation failed", e);
      }
    }
  }

  static void addSelectorTimeoutTask(Runnable r) {
    timeoutTasks.add(r);
  }

  private static void processReadyKeys() {
    Iterator<SelectionKey> it = selector.selectedKeys().iterator();
    while (it.hasNext()) {
      SelectionKey key = it.next();
      it.remove();
      KeyProcessor t = (KeyProcessor) key.attachment();
      t.processReadyKey(key);
    }
  }

  static void verboseLog(String prefix, SocketAddress local, SocketAddress remote, byte[] data) {
    if (log.isTraceEnabled()) {
      log.trace(hexdump.dump(prefix, data));
    }
    if (packetLogger != null) {
      packetLogger.log(prefix, local, remote, data);
    }
  }

  static void setPacketLogger(PacketLogger logger) {
    packetLogger = logger;
  }
}

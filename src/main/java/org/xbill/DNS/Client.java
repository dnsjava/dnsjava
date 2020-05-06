// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.ClosedSelectorException;
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

  private static volatile boolean run = true;
  private static final List<Runnable> timeoutTasks = new CopyOnWriteArrayList<>();
  private static final List<Runnable> closeTasks = new CopyOnWriteArrayList<>();
  private static Thread selectorThread;
  private static volatile Selector selector;

  interface KeyProcessor {
    void processReadyKey(SelectionKey key);
  }

  static Selector selector() throws IOException {
    if (selector == null) {
      synchronized (Client.class) {
        if (selector == null) {
          selector = Selector.open();
          log.debug("Starting dnsjava NIO selector thread");
          selectorThread = new Thread(Client::runSelector);
          selectorThread.setDaemon(true);
          selectorThread.setName("dnsjava NIO selector");
          selectorThread.start();
          Thread closeThread = new Thread(Client::close);
          closeThread.setName("dnsjava NIO shutdown hook");
          Runtime.getRuntime().addShutdownHook(closeThread);
        }
      }
    }

    return selector;
  }

  private static void close() {
    run = false;
    closeTasks.forEach(Runnable::run);
    timeoutTasks.clear();
    selector.wakeup();
    try {
      selector.close();
      selectorThread.join();
    } catch (InterruptedException | IOException e) {
      log.warn("Failed to properly shutdown", e);
    }
  }

  private static void runSelector() {
    while (run) {
      try {
        if (selector.select(1000) == 0) {
          timeoutTasks.forEach(Runnable::run);
        }

        if (run) {
          processReadyKeys();
        }
      } catch (IOException e) {
        log.error("A selection operation failed", e);
      } catch (ClosedSelectorException e) {
        // ignore
      }
    }
    log.debug("dnsjava NIO selector thread stopped");
  }

  static void addSelectorTimeoutTask(Runnable r) {
    timeoutTasks.add(r);
  }

  static void addCloseTask(Runnable r) {
    closeTasks.add(r);
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

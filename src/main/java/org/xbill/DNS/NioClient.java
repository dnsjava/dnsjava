// SPDX-License-Identifier: BSD-3-Clause
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
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.utils.hexdump;

/**
 * Manages the network I/O for the {@link SimpleResolver}. It is mostly an implementation detail of
 * {@code dnsjava} and the only method intended to be called is {@link #close()} - and only if
 * {@code dnsjava} is used in an application container like Tomcat. In a normal JVM setup {@link
 * #close()} is called by a shutdown hook.
 *
 * @since 3.4
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.NONE)
public abstract class NioClient {
  /** Packet logger, if available. */
  private static PacketLogger packetLogger = null;

  private static final List<Runnable> timeoutTasks = new CopyOnWriteArrayList<>();
  private static final List<Runnable> closeTasks = new CopyOnWriteArrayList<>();
  private static Thread selectorThread;
  private static Thread closeThread;
  private static volatile Selector selector;
  private static volatile boolean run;

  interface KeyProcessor {
    void processReadyKey(SelectionKey key);
  }

  static Selector selector() throws IOException {
    if (selector == null) {
      synchronized (NioClient.class) {
        if (selector == null) {
          selector = Selector.open();
          log.debug("Starting dnsjava NIO selector thread");
          run = true;
          selectorThread = new Thread(NioClient::runSelector);
          selectorThread.setDaemon(true);
          selectorThread.setName("dnsjava NIO selector");
          selectorThread.start();
          closeThread = new Thread(() -> close(true));
          closeThread.setName("dnsjava NIO shutdown hook");
          Runtime.getRuntime().addShutdownHook(closeThread);
        }
      }
    }

    return selector;
  }

  /** Shutdown the network I/O used by the {@link SimpleResolver}. */
  public static void close() {
    close(false);
  }

  private static void close(boolean fromHook) {
    run = false;

    if (!fromHook) {
      try {
        Runtime.getRuntime().removeShutdownHook(closeThread);
      } catch (Exception ex) {
        log.warn("Failed to remove shutdown hoook, ignoring and continuing close");
      }
    }

    for (Runnable closeTask : closeTasks) {
      try {
        closeTask.run();
      } catch (Exception e) {
        log.warn("Failed to execute a shutdown task, ignoring and continuing close", e);
      }
    }

    selector.wakeup();

    try {
      selector.close();
    } catch (IOException e) {
      log.warn("Failed to properly close selector, ignoring and continuing close", e);
    }

    try {
      selectorThread.join();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } finally {
      synchronized (NioClient.class) {
        selector = null;
        selectorThread = null;
        closeThread = null;
      }
    }
  }

  private static void runSelector() {
    int selectorTimeout = Options.intValue("selectorTimeout");
    int timeout = selectorTimeout >= 0 ? selectorTimeout : 1000; // Default 1000.

    while (run) {
      try {
        if (selector.select(timeout) == 0) {
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

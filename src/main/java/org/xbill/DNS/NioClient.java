// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.function.Consumer;
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
 * <p>The following configuration parameter is available:
 *
 * <dl>
 *   <dt>{@value SELECTOR_TIMEOUT_PROPERTY}
 *   <dd>Set selector timeout in milliseconds. Default/Max 1000, Min 1.
 *   <dt>{@value REGISTER_SHUTDOWN_HOOK_PROPERTY}
 *   <dd>Register Shutdown Hook termination of NIO. Default True.
 * </dl>
 *
 * @since 3.4
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.NONE)
public abstract class NioClient {
  static final String SELECTOR_TIMEOUT_PROPERTY = "dnsjava.nio.selector_timeout";
  static final String REGISTER_SHUTDOWN_HOOK_PROPERTY = "dnsjava.nio.register_shutdown_hook";
  private static final Object NIO_CLIENT_LOCK = new Object();

  /** Packet logger, if available. */
  private static PacketLogger packetLogger = null;

  private static final Runnable[] TIMEOUT_TASKS = new Runnable[2];
  private static final Runnable[] CLOSE_TASKS = new Runnable[2];

  private static Consumer<Selector> tcpRegistrationsTask;
  private static Consumer<Selector> udpRegistrationsTask;

  private static Thread selectorThread;
  private static Thread closeThread;
  private static volatile Selector selector;
  private static volatile boolean run;
  private static volatile boolean closeDone;

  interface KeyProcessor {
    void processReadyKey(SelectionKey key);
  }

  static Selector selector() throws IOException {
    if (selector == null) {
      synchronized (NIO_CLIENT_LOCK) {
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
          if (Boolean.parseBoolean(System.getProperty(REGISTER_SHUTDOWN_HOOK_PROPERTY, "true"))) {
            Runtime.getRuntime().addShutdownHook(closeThread);
          }
        }
      }
    }

    return selector;
  }

  /**
   * Shutdown the network I/O used by the {@link SimpleResolver}.
   *
   * @implNote Does not wait until the selector thread has stopped. But users may immediately start
   *     using the {@link NioClient} again.
   * @since 3.4.0
   */
  public static void close() {
    close(false);
  }

  private static void close(boolean fromHook) {
    log.debug("Closing dnsjava NIO selector, fromHook={}", fromHook);
    run = false;
    Selector localSelector = selector;
    if (localSelector != null) {
      selector.wakeup();
    }

    if (!fromHook) {
      synchronized (NIO_CLIENT_LOCK) {
        if (closeThread != null) {
          try {
            Runtime.getRuntime().removeShutdownHook(closeThread);
          } catch (Exception ex) {
            log.warn("Failed to remove shutdown hook, ignoring and continuing close", ex);
          }
        }
      }
    }

    if (localSelector == null) {
      // Prevent hanging when close() was called without starting
      return;
    }

    synchronized (NIO_CLIENT_LOCK) {
      try {
        while (!closeDone) {
          NIO_CLIENT_LOCK.wait();
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } finally {
        closeDone = false;
      }
    }
  }

  static void runSelector() {
    int timeout = Integer.getInteger(SELECTOR_TIMEOUT_PROPERTY, 1000);

    if (timeout <= 0 || timeout > 1000) {
      throw new IllegalArgumentException("Invalid selector_timeout, must be between 1 and 1000");
    }

    while (run) {
      try {
        int numSelects = selector.select(timeout);
        if (Thread.currentThread().isInterrupted()) {
          log.debug("Sector thread was interrupted, stopping");
          close();
          break;
        }

        if (numSelects == 0) {
          runTasks(TIMEOUT_TASKS);
        }

        if (run) {
          runRegistrationTasks();
          processReadyKeys();
        }
      } catch (IOException e) {
        log.error("A selection operation failed", e);
      } catch (ClosedSelectorException e) {
        // ignore
      }
    }

    runClose();
    log.debug("dnsjava NIO selector thread stopped");
  }

  private static void runClose() {
    try {
      runTasks(CLOSE_TASKS);
    } catch (Exception e) {
      log.warn("Failed to execute shutdown task, ignoring and continuing close", e);
    }

    Selector localSelector = selector;
    Thread localSelectorThread = selectorThread;
    synchronized (NIO_CLIENT_LOCK) {
      selector = null;
      selectorThread = null;
      closeThread = null;
      closeDone = true;
      NIO_CLIENT_LOCK.notifyAll();
    }

    if (localSelector != null) {
      try {
        localSelector.close();
      } catch (IOException e) {
        log.warn("Failed to properly close selector, ignoring and continuing close", e);
      }
    }

    if (localSelectorThread != null) {
      try {
        localSelectorThread.join();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }

  static void setTimeoutTask(Runnable r, boolean isTcpClient) {
    addTask(TIMEOUT_TASKS, r, isTcpClient);
  }

  static void setRegistrationsTask(Consumer<Selector> r, boolean isTcpClient) {
    if (isTcpClient) {
      tcpRegistrationsTask = r;
    } else {
      udpRegistrationsTask = r;
    }
  }

  static void setCloseTask(Runnable r, boolean isTcpClient) {
    addTask(CLOSE_TASKS, r, isTcpClient);
  }

  private static void addTask(Runnable[] tasks, Runnable r, boolean isTcpClient) {
    if (isTcpClient) {
      tasks[0] = r;
    } else {
      tasks[1] = r;
    }
  }

  private static void runTasks(Runnable[] runnables) {
    Runnable r0 = runnables[0];
    if (r0 != null) {
      r0.run();
    }
    Runnable r1 = runnables[1];
    if (r1 != null) {
      r1.run();
    }
  }

  private static void runRegistrationTasks() {
    Consumer<Selector> tcpTask = tcpRegistrationsTask;
    if (tcpTask != null) {
      tcpTask.accept(selector);
    }
    Consumer<Selector> udpTask = udpRegistrationsTask;
    if (udpTask != null) {
      udpTask.accept(selector);
    }
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

  static void verboseLog(
      String prefix, SocketAddress local, SocketAddress remote, ByteBuffer data) {
    if (log.isTraceEnabled() || packetLogger != null) {
      byte[] dst = new byte[data.remaining()];
      int pos = data.position();
      data.get(dst, 0, data.remaining());
      data.position(pos);
      verboseLog(prefix, local, remote, dst);
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

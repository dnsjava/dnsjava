//package org.xbill.DNS;
//
//import java.io.IOException;
//import java.nio.channels.SelectableChannel;
//import java.nio.channels.SelectionKey;
//import java.nio.channels.Selector;
//import java.util.*;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.concurrent.Executors;
//import java.util.concurrent.ScheduledExecutorService;
//import java.util.concurrent.TimeUnit;
//
//import lombok.Getter;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.xbill.DNS.io.IoClientFactory;
//import org.xbill.DNS.io.TcpIoClient;
//import org.xbill.DNS.io.UdpIoClient;
//
//@Getter
//@Slf4j
//public class Socks5ProxyIoClientFactory implements IoClientFactory {
//
//  // SOCKS5 proxy configuration
//  private final Socks5ProxyConfig config;
//
//  // connection pool Socks5ProxyConnection
//  private static final Map<String, Map<String, Socks5Proxy>> socks5ConnectionPool = new ConcurrentHashMap<>();
//
//  // selector for handling IO events
//  private volatile Selector selector;
//  private Thread eventLoopThread;
//  private volatile boolean eventLoopRunning = false;
//
//  // scheduler for handling timeouts, cleanup and closing connections
//  private ScheduledExecutorService timeoutScheduler;
//  private static final long timeout = 30000; // 30 seconds timeout
//  private final Map<SelectionKey, Long> keyTimestamps = new ConcurrentHashMap<>();
//
//  // constructor
//  public Socks5ProxyIoClientFactory(Socks5ProxyConfig socks5Proxy) {
//    config = Objects.requireNonNull(socks5Proxy, "proxy config must not be null");
//
//    // start event loop if not already running
//    startEventLoop();
//
//    // Add shutdown hook for graceful shutdown
//    Runtime.getRuntime().addShutdownHook(new Thread(this::stopEventLoop));
//  }
//
//  // method to start the event loop
//  private synchronized void startEventLoop() {
//    try {
//      selector = Selector.open();
//    } catch (IOException e) {
//      log.error("Error opening selector", e);
//      return;
//    }
//
//    eventLoopRunning = true;
//    timeoutScheduler = Executors.newScheduledThreadPool(1);
//    eventLoopThread = new Thread(() -> {
//      try {
//        while (eventLoopRunning) {
//          // blocking call, waits for an io event
//          selector.select();
//
//          // get the set of keys with pending events
//          Set<SelectionKey> selectedKeys = selector.selectedKeys();
//          Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
//          while (keyIterator.hasNext()) {
//            SelectionKey key = keyIterator.next();
//            keyIterator.remove();
//            if (key.isValid()) {
//              // run the task associated with the key
//              ((Runnable) key.attachment()).run();
//              // update the timestamp for the key
////              long currentTime = System.currentTimeMillis();
////              keyTimestamps.put(key, currentTime);
////              scheduleTimeout(selector, key);
//            }
//          }
//        }
//      } catch (IOException e) {
//        log.error("Error in event loop", e);
//      } finally {
//        try {
//          if (selector != null) {
//            selector.close();
//          }
//        } catch (IOException e) {
//          log.error("Error closing selector", e);
//        }
//        eventLoopRunning = false;
//      }
//    });
//    eventLoopThread.start();
//  }
//
//  private void scheduleTimeout(Selector selector, SelectionKey key) {
//    timeoutScheduler.schedule(() -> {
//      long currentTime = System.currentTimeMillis();
//      if (currentTime - keyTimestamps.getOrDefault(key, 0L) > timeout) {
//        log.debug("Closing connection due to timeout");
//        try {
//          key.cancel();
//          key.channel().close();
//        } catch (IOException e) {
//          log.error("Error closing channel due to timeout", e);
//        }
//        keyTimestamps.remove(key);
//        selector.wakeup();
//      }
//    }, timeout, TimeUnit.MILLISECONDS);
//  }
//
//  // graceful shutdown of the event loop
//  public void stopEventLoop() {
//    // stop the event loop
//    eventLoopRunning = false;
//    if (eventLoopThread != null) {
//      eventLoopThread.interrupt();
//    }
//    // stop the timeout scheduler
//    if (timeoutScheduler != null) {
//      timeoutScheduler.shutdownNow();
//    }
//    // close all connections in the pool
//    for (Map<String, Socks5Proxy> subConnections : socks5ConnectionPool.values()) {
//      for (Socks5Proxy connection : subConnections.values()) {
//        try {
//          connection.getTcpSelectionKey().channel().close();
//          connection.getTcpSelectionKey().cancel();
//        } catch (IOException e) {
//          log.error("Error closing connection", e);
//        }
//      }
//    }
//    // close the selector
//    try {
//      selector.close();
//    } catch (IOException e) {
//      log.error("Error closing selector", e);
//    }
//    socks5ConnectionPool.clear();
//  }
//
//  // check if the event loop thread is alive for health checks
//  public boolean isEventLoopThreadAlive() {
//    return eventLoopThread != null && eventLoopThread.isAlive();
//  }
//
//  // check if the timeout scheduler is running for health checks
//  public boolean isTimeoutSchedulerRunning() {
//    return timeoutScheduler != null && !timeoutScheduler.isShutdown();
//  }
//
//  // check if the event loop is healthy overall
//  public boolean isEventLoopHealthy() {
//    return isEventLoopThreadAlive() && isTimeoutSchedulerRunning();
//  }
//
//  // register a new connection to the selector
//  public SelectionKey registerToSelector(SelectableChannel conn) throws IOException {
//    return conn.register(selector, SelectionKey.OP_CONNECT);
//  }
//
//  // unregister a connection from the selector
//  public synchronized void unregisterFromSelector(
//    PoolConn poolConn,
//    Throwable ex) throws IOException {
//    if (
//        ex == null
//        && poolConn.getSocks5Conn().getTcpSelectionKey().isValid()
//        && poolConn.getSocks5Conn().getTcpSelectionKey().channel().isOpen()
//    ) {
//      // unregister for reuse
//      poolConn.getSocks5Conn().getTcpSelectionKey().cancel();
//    } else {
//      // clean up the socks connection instance in case of an exception or invalid state
//      cleanupConnectionFromPool(poolConn);
//    }
//  }
//
//  public synchronized PoolConn getPoolConnFromPool(String connectionID) {
//    Map<String, Socks5Proxy> subConnections = socks5ConnectionPool.get(connectionID);
//    if (subConnections != null && !subConnections.isEmpty()) {
//      for (Map.Entry<String, Socks5Proxy> entry : subConnections.entrySet()) {
//        Socks5Proxy socks5Conn = entry.getValue();
//        if (socks5Conn.getTcpSelectionKey().channel().isOpen()
//          && !socks5Conn.getTcpSelectionKey().channel().isRegistered()) {
//          return new PoolConn(connectionID, entry.getKey(), socks5Conn);
//        }
//      }
//    }
//    return null;
//  }
//
//  @Getter
//  @RequiredArgsConstructor
//  public static class PoolConn {
//    private final String connectionID;
//    private final String subConnectionID;
//    private final Socks5Proxy socks5Conn;
//  }
//
//  public synchronized PoolConn addConnectionToPool(String connectionID, Socks5Proxy socks5Conn) {
//    String subConnectionID = UUID.randomUUID().toString();
//    socks5ConnectionPool.computeIfAbsent(connectionID, k -> new ConcurrentHashMap<>()).put(subConnectionID, socks5Conn);
//    return new PoolConn(connectionID, subConnectionID, socks5Conn);
//  }
//
//  public synchronized void cleanupConnectionFromPool(PoolConn poolConn) throws IOException {
//    if (poolConn.getSocks5Conn() != null && poolConn.getSocks5Conn().getTcpSelectionKey() != null) {
//      poolConn.getSocks5Conn().getTcpSelectionKey().channel().close();
//      poolConn.getSocks5Conn().getTcpSelectionKey().cancel();
//    }
//    Map<String, Socks5Proxy> subConnections = socks5ConnectionPool.get(poolConn.getConnectionID());
//    if (subConnections != null) {
//      subConnections.remove(poolConn.getSubConnectionID());
//      if (subConnections.isEmpty()) {
//        socks5ConnectionPool.remove(poolConn.getConnectionID());
//      }
//    }
//  }
//
//  @Override
//  public TcpIoClient createOrGetTcpClient() {
//    return new Socks5ProxyTcpIoClient(this, config);
//  }
//
//  @Override
//  public UdpIoClient createOrGetUdpClient() {
//    return new Socks5ProxyUdpIoClient(this, config);
//  }
//}

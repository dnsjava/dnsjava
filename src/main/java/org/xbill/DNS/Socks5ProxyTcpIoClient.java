//package org.xbill.DNS;
//
//import lombok.extern.slf4j.Slf4j;
//import org.xbill.DNS.io.TcpIoClient;
//
//import java.io.IOException;
//import java.net.InetSocketAddress;
//import java.nio.ByteBuffer;
//import java.nio.channels.SelectionKey;
//import java.nio.channels.SocketChannel;
//import java.time.Duration;
//import java.util.concurrent.CompletableFuture;
//
//@Slf4j
//public class Socks5ProxyTcpIoClient implements TcpIoClient {
//  private final Socks5ProxyIoClientFactory factory;
//  private final Socks5ProxyConfig config;
//  private Socks5ProxyIoClientFactory.PoolConn poolConn;
//
//  public Socks5ProxyTcpIoClient(Socks5ProxyIoClientFactory factory, Socks5ProxyConfig config) {
//    this.factory = factory;
//    this.config = config;
//  }
//
//  public void initOrReuseConn(CompletableFuture<Void> f, String keyString, InetSocketAddress local, InetSocketAddress remote) {
//    Socks5ProxyIoClientFactory.PoolConn poolConn = factory.getPoolConnFromPool(keyString);
//    try {
//      if (poolConn == null || !poolConn.getSocks5Conn().getTcpSelectionKey().channel().isOpen()) {
//        SocketChannel tcpConn = SocketChannel.open();
//        tcpConn.configureBlocking(false);
//        SelectionKey selectionKey = factory.registerToSelector(tcpConn);
//        Socks5Proxy socks5Conn = new Socks5Proxy(selectionKey, config, local, remote, Socks5Proxy.Command.CONNECT);
//        tcpConn.connect(config.getProxyAddress());
//        socks5Conn.handleSOCKS5(f);
//        this.poolConn = factory.addConnectionToPool(keyString, socks5Conn);
//      } else {
//        SelectionKey selectionKey = factory.registerToSelector(poolConn.getSocks5Conn().getTcpSelectionKey().channel());
//        poolConn.getSocks5Conn().setTcpSelectionKey(selectionKey);
//        this.poolConn = poolConn;
//        f.complete(null);
//      }
//    } catch (IOException e) {
//      f.completeExceptionally(e);
//    }
//  }
//
//  @Override
//  public CompletableFuture<byte[]> sendAndReceiveTcp(
//    InetSocketAddress local,
//    InetSocketAddress remote,
//    Message query,
//    byte[] data,
//    Duration timeout) {
//    if (local == null) {
//      local = new InetSocketAddress(0);
//    }
//    // keyString is used to identify and reuse SOCKS5 connections
//    String keyString = local.toString() + "-" + remote.toString() + "-TCP";
//    CompletableFuture<Void> socksF = new CompletableFuture<>();
//    this.initOrReuseConn(socksF, keyString, local, remote);
//
//    return socksF.thenComposeAsync(v -> {
//      CompletableFuture<byte[]> dataF = new CompletableFuture<>();
//      try {
//        poolConn.getSocks5Conn().getTcpSelectionKey().attach(new SendHandler(dataF, data, poolConn.getSocks5Conn().getTcpSelectionKey()));
//        poolConn.getSocks5Conn().getTcpSelectionKey().interestOps(SelectionKey.OP_WRITE);
//        poolConn.getSocks5Conn().getTcpSelectionKey().selector().wakeup();
//      } catch (Exception e) {
//        dataF.completeExceptionally(e);
//      }
//      return dataF;
//    }).whenComplete((result, ex) -> {
//      try {
//        factory.unregisterFromSelector(poolConn, ex);
//      } catch (IOException e) {
//        throw new RuntimeException(e);
//      }
//    });
//  }
//
//  private class SendHandler implements Runnable {
//    private final CompletableFuture<byte[]> future;
//    private final byte[] data;
//    private final SelectionKey selectionKey;
//
//    public SendHandler(CompletableFuture<byte[]> future, byte[] data, SelectionKey selectionKey) {
//      this.future = future;
//      this.data = data;
//      this.selectionKey = selectionKey;
//    }
//
//    @Override
//    public void run() {
//      try {
//        SocketChannel channel = (SocketChannel) selectionKey.channel();
//        ByteBuffer buffer = ByteBuffer.allocate(data.length + 2);
//        buffer.put((byte) (data.length >>> 8));
//        buffer.put((byte) (data.length & 0xFF));
//        buffer.put(data);
//        buffer.flip();
//        while (buffer.hasRemaining()) {
//          channel.write(buffer);
//        }
//        selectionKey.attach(new ReceiveHandler(future, selectionKey));
//        selectionKey.interestOps(SelectionKey.OP_READ);
//        selectionKey.selector().wakeup();
//      } catch (IOException e) {
//        future.completeExceptionally(e);
//      }
//    }
//  }
//
//  private class ReceiveHandler implements Runnable {
//    private final CompletableFuture<byte[]> future;
//    private final SelectionKey selectionKey;
//    private final ByteBuffer responseLengthData = ByteBuffer.allocate(2);
//    private ByteBuffer responseData;
//
//    public ReceiveHandler(CompletableFuture<byte[]> future, SelectionKey selectionKey) {
//      this.future = future;
//      this.selectionKey = selectionKey;
//    }
//
//    @Override
//    public void run() {
//      try {
//        SocketChannel channel = (SocketChannel) selectionKey.channel();
//        if (responseData == null) {
//          int read = channel.read(responseLengthData);
//          if (read < 0) {
//            throw new IOException("Connection closed by peer");
//          }
//          if (responseLengthData.position() == 2) {
//            responseLengthData.flip();
//            int length = ((responseLengthData.get(0) & 0xFF) << 8) + (responseLengthData.get(1) & 0xFF);
//            responseData = ByteBuffer.allocate(length);
//          }
//        }
//        if (responseData != null) {
//          int read = channel.read(responseData);
//          if (read < 0) {
//            throw new IOException("Connection closed by peer");
//          }
//          if (!responseData.hasRemaining()) {
//            responseData.flip();
//            byte[] data = new byte[responseData.limit()];
//            responseData.get(data);
//            future.complete(data);
//          }
//        }
//      } catch (IOException e) {
//        future.completeExceptionally(e);
//      }
//    }
//  }
//}

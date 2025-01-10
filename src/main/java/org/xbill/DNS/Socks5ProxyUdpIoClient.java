//package org.xbill.DNS;
//
//import org.xbill.DNS.io.UdpIoClient;
//
//import java.io.EOFException;
//import java.io.IOException;
//import java.net.InetSocketAddress;
//import java.nio.ByteBuffer;
//import java.nio.channels.DatagramChannel;
//import java.nio.channels.SelectionKey;
//import java.nio.channels.SocketChannel;
//import java.time.Duration;
//import java.util.concurrent.CompletableFuture;
//
//public class Socks5ProxyUdpIoClient implements UdpIoClient {
//  private final Socks5ProxyIoClientFactory factory;
//  private Socks5ProxyIoClientFactory.PoolConn poolConn;
//  private SelectionKey udpSelectionKey;
//  private final Socks5ProxyConfig config;
//  private int max;
//
//  public Socks5ProxyUdpIoClient(
//    Socks5ProxyIoClientFactory factory,
//    Socks5ProxyConfig config) {
//    this.factory = factory;
//    this.config = config;
//  }
//
//  public void initOrReuseConn(CompletableFuture<Void> f, String keyString, InetSocketAddress local, InetSocketAddress remote) {
//    Socks5ProxyIoClientFactory.PoolConn poolConn = factory.getPoolConnFromPool(keyString);
//    try {
//      if (poolConn == null) {
//        SocketChannel tcpConn = SocketChannel.open();
//        tcpConn.configureBlocking(false);
//        SelectionKey selectionKey = factory.registerToSelector(tcpConn);
//        Socks5Proxy socks5Conn = new Socks5Proxy(selectionKey, config, local, remote, Socks5Proxy.Command.UDP_ASSOCIATE);
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
//
//  @Override
//  public CompletableFuture<byte[]> sendAndReceiveUdp(
//    InetSocketAddress local,
//    InetSocketAddress remote,
//    Message query,
//    byte[] data,
//    int max,
//    Duration timeout) {
//    this.max = max;
//    InetSocketAddress finalLocal;
//    if (local == null) {
//      finalLocal = new InetSocketAddress(0);
//    } else {
//      finalLocal = local;
//    }
//    // keyString is used to identify and reuse SOCKS5 connections
//    String keyString = finalLocal.toString() + "-" + remote.toString() + "-UDP";
//    CompletableFuture<Void> socksF = new CompletableFuture<>();
//    this.initOrReuseConn(socksF, keyString, finalLocal, remote);
//
//
//    return socksF.thenComposeAsync(v -> {
//      CompletableFuture<byte[]> dataF = new CompletableFuture<>();
//      try {
//        udpSelectionKey = this.poolConn.getSocks5Conn().getUdpChannel().register(factory.getSelector(), SelectionKey.OP_READ);
//        udpSelectionKey.selector().wakeup();
//
//        udpSelectionKey.attach(new SendHandler(dataF, data, udpSelectionKey));
//        udpSelectionKey.interestOps(SelectionKey.OP_WRITE);
//        udpSelectionKey.selector().wakeup();
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
//        DatagramChannel channel = (DatagramChannel) selectionKey.channel();
//        ByteBuffer buffer = poolConn.getSocks5Conn().addSocks5UdpAssociateHeader(data);
//        int headerLength = buffer.position()-data.length;
//        buffer.flip();
//        while (buffer.hasRemaining()) {
//          channel.write(buffer);
//        }
//        selectionKey.attach(new ReceiveHandler(future, selectionKey, headerLength));
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
//    private final int headerLength;
//
//    public ReceiveHandler(CompletableFuture<byte[]> future, SelectionKey selectionKey, int headerLength) {
//      this.future = future;
//      this.selectionKey = selectionKey;
//      this.headerLength = headerLength;
//    }
//
//    @Override
//    public void run() {
//      try {
//        DatagramChannel channel = (DatagramChannel) selectionKey.channel();
//        ByteBuffer responseData = ByteBuffer.allocate(max);
//        int read = channel.read(responseData);
//        if (read < 0) {
//          throw new EOFException();
//        }
//
//        int length = responseData.position() - headerLength;
//        byte[] data = new byte[length];
//        responseData.position(headerLength);
//        responseData.get(data, 0, length);
//        future.complete(data);
//
//        selectionKey.cancel();
//      } catch (IOException e) {
//        future.completeExceptionally(e);
//      }
//    }
//  }
//}

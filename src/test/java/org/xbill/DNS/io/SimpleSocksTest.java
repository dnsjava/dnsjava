package org.xbill.DNS.io;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;


public class SimpleSocksTest extends AbstractSocksTest {

  @Test
  public void testUDP() throws IOException {
    environment.start();

    SimpleResolver res = new SimpleResolver();
    InetSocketAddress proxyAddress = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1080);
    NioSocks5ProxyConfig config = new NioSocks5ProxyConfig(proxyAddress);
    res.setIoClientFactory(new NioSocks5ProxyFactory(config));

    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    System.out.println(response);

    environment.stop();
  }

  @Test
  public void testTCP() throws IOException {
    environment.start();

    SimpleResolver res = new SimpleResolver("10.5.0.2");
    InetSocketAddress proxyAddress = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1080);
    NioSocks5ProxyConfig config = new NioSocks5ProxyConfig(proxyAddress);
    res.setIoClientFactory(new NioSocks5ProxyFactory(config));
    res.setTCP(true);

    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    System.out.println(response);

    environment.stop();
  }

  @Test
  public void testAuth() throws IOException {
    environment.start();

    SimpleResolver res = new SimpleResolver();
    InetSocketAddress proxyAddress = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1080);
    String socks5User = "me";
    String socks5Password = "42";
    NioSocks5ProxyConfig config = new NioSocks5ProxyConfig(proxyAddress, socks5User, socks5Password);
    res.setIoClientFactory(new NioSocks5ProxyFactory(config));

    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    System.out.println(response);

    environment.stop();
  }

}

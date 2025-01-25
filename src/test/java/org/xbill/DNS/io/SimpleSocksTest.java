package org.xbill.DNS.io;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SimpleSocksTest extends AbstractSocksTest {

  @BeforeAll
  public static void setUp() throws IOException {
    environment.start();
  }

  @AfterAll
  public static void tearDown() throws IOException {
    environment.stop();
  }

  private SimpleResolver createResolver(String address, boolean useTCP, String user, String password) throws IOException {
    SimpleResolver res = address == null ? new SimpleResolver() : new SimpleResolver(address);
    InetSocketAddress proxyAddress = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1080);
    NioSocks5ProxyConfig config = user == null ? new NioSocks5ProxyConfig(proxyAddress) : new NioSocks5ProxyConfig(proxyAddress, user, password);
    res.setIoClientFactory(new NioSocks5ProxyFactory(config));
    res.setTCP(useTCP);
    return res;
  }

  @Test
  public void testUDP() throws IOException {
    SimpleResolver res = createResolver(null, false, null, null);
    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    assertNotNull(response);
  }

  @Test
  public void testTCP() throws IOException {
    SimpleResolver res = createResolver("10.5.0.2", true, null, null);
    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    assertNotNull(response);
  }

  @Test
  public void testAuth() throws IOException {
    SimpleResolver res = createResolver(null, false, "me", "42");
    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    assertNotNull(response);
  }
}

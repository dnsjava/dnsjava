// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.io;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NioSocks5ProxyConfig;
import org.xbill.DNS.NioSocks5ProxyFactory;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class SimpleSocksTest {
  static final ComposeContainer environment =
      new ComposeContainer(new File("src/test/resources/compose/compose.yml"))
          .withBuild(true)
          .waitingFor("dante-socks5", Wait.forHealthcheck());

  @BeforeAll
  public static void setUp() throws IOException, InterruptedException {
    environment.start();
    // wait to make sure the container is ready
    Thread.sleep(100);
  }

  @AfterAll
  public static void tearDown() {
    environment.stop();
  }

  private SimpleResolver createResolver(
      String address, boolean useTCP, String user, String password) throws IOException {
    SimpleResolver res = address == null ? new SimpleResolver() : new SimpleResolver(address);
    InetSocketAddress proxyAddress =
        new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1080);
    NioSocks5ProxyConfig config =
        user == null
            ? new NioSocks5ProxyConfig(proxyAddress)
            : new NioSocks5ProxyConfig(proxyAddress, user, password);
    res.setIoClientFactory(new NioSocks5ProxyFactory(config));
    res.setTCP(useTCP);
    return res;
  }

  @Test
  public void testUDP() throws IOException {
    SimpleResolver res = createResolver("10.5.0.2", false, null, null);
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
    SimpleResolver res = createResolver("10.5.0.2", false, "me", "42");
    Record rec = Record.newRecord(Name.fromString("simple.test", Name.root), Type.A, DClass.IN);
    Message query = Message.newQuery(rec);
    Message response = res.send(query);
    assertNotNull(response);
  }
}

// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.xbill.DNS.config.PropertyResolverConfigProvider.DNS_NDOTS_PROP;
import static org.xbill.DNS.config.PropertyResolverConfigProvider.DNS_SEARCH_PROP;
import static org.xbill.DNS.config.PropertyResolverConfigProvider.DNS_SERVER_PROP;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.xbill.DNS.config.InitializationException;
import org.xbill.DNS.config.JndiContextResolverConfigProvider;
import org.xbill.DNS.config.PropertyResolverConfigProvider;
import org.xbill.DNS.config.ResolvConfResolverConfigProvider;
import org.xbill.DNS.config.SunJvmResolverConfigProvider;
import org.xbill.DNS.config.WindowsResolverConfigProvider;

class ResolverConfigTest {
  @Test
  void testSkipInit() throws Exception {
    Field configProvidersField = ResolverConfig.class.getDeclaredField("configProviders");
    configProvidersField.setAccessible(true);
    configProvidersField.set(null, null);
    try {
      System.setProperty(ResolverConfig.CONFIGPROVIDER_SKIP_INIT, Boolean.TRUE.toString());
      assertTrue(ResolverConfig.getConfigProviders().isEmpty());
    } finally {
      System.setProperty(ResolverConfig.CONFIGPROVIDER_SKIP_INIT, Boolean.FALSE.toString());
      configProvidersField.set(null, null);
    }
  }

  @Test
  void properties() {
    String[] dnsServers1 = {"192.168.1.1", "192.168.1.2", "192.168.1.1"};
    String[] dnsServers2 = {"192.168.1.3"};
    // intentionally adding duplicate search entries for testing
    String[] dnsSearch = {"dnsjava.org", "example.com", "dnsjava.org"};
    Name[] searchPath =
        Arrays.stream(dnsSearch).map(s -> Name.fromConstantString(s + ".")).toArray(Name[]::new);
    System.setProperty(DNS_SERVER_PROP, String.join(",", dnsServers1));
    System.setProperty(DNS_SEARCH_PROP, String.join(",", dnsSearch));
    System.setProperty(DNS_NDOTS_PROP, String.valueOf(5));
    try {
      PropertyResolverConfigProvider rc = new PropertyResolverConfigProvider();
      assertTrue(rc.isEnabled());
      rc.initialize();

      assertEquals(2, rc.servers().size());
      assertEquals(dnsServers1[0], rc.servers().get(0).getAddress().getHostAddress());

      // must remove no longer present servers
      System.setProperty(DNS_SERVER_PROP, String.join(",", dnsServers2));
      rc.initialize();
      assertEquals(1, rc.servers().size());

      // any duplicate suffixes should be excluded
      assertEquals(2, rc.searchPaths().size());
      assertEquals(searchPath[0], rc.searchPaths().get(0));
      assertEquals(searchPath[1], rc.searchPaths().get(1));

      assertEquals(5, rc.ndots());
    } finally {
      System.clearProperty(DNS_SERVER_PROP);
      System.clearProperty(DNS_SEARCH_PROP);
      System.clearProperty(DNS_NDOTS_PROP);
    }
  }

  @Test
  void propertiesWithPort() {
    String[] dnsServers = {
      "192.168.1.1", "192.168.1.1:54", "::1", "0:0:0:0:0:0:0:1", "[::1]:54", "[::2]"
    };
    System.setProperty(DNS_SERVER_PROP, String.join(",", dnsServers));
    try {
      PropertyResolverConfigProvider rc = new PropertyResolverConfigProvider();
      rc.initialize();

      assertEquals(5, rc.servers().size());
      assertEquals("192.168.1.1", rc.servers().get(0).getAddress().getHostAddress());
      assertEquals(SimpleResolver.DEFAULT_PORT, rc.servers().get(0).getPort());

      assertEquals("192.168.1.1", rc.servers().get(1).getAddress().getHostAddress());
      assertEquals(54, rc.servers().get(1).getPort());

      assertEquals("0:0:0:0:0:0:0:1", rc.servers().get(2).getAddress().getHostAddress());
      assertEquals(SimpleResolver.DEFAULT_PORT, rc.servers().get(2).getPort());

      assertEquals("0:0:0:0:0:0:0:1", rc.servers().get(3).getAddress().getHostAddress());
      assertEquals(54, rc.servers().get(3).getPort());

      assertEquals("0:0:0:0:0:0:0:2", rc.servers().get(4).getAddress().getHostAddress());
      assertEquals(53, rc.servers().get(4).getPort());
    } finally {
      System.clearProperty(DNS_SERVER_PROP);
    }
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void resolvConfDisabledOnWindows() {
    ResolvConfResolverConfigProvider rc = new ResolvConfResolverConfigProvider();
    assertFalse(rc.isEnabled());
  }

  @Test
  @DisabledOnOs(OS.WINDOWS)
  void resolvConfEnabledOnUnix() {
    ResolvConfResolverConfigProvider rc = new ResolvConfResolverConfigProvider();
    assertTrue(rc.isEnabled());
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void windowsEnabledOnWindows() {
    WindowsResolverConfigProvider rc = new WindowsResolverConfigProvider();
    assertTrue(rc.isEnabled());
  }

  @Test
  @DisabledOnOs(OS.WINDOWS)
  void windowsDisabledOnUnix() {
    WindowsResolverConfigProvider rc = new WindowsResolverConfigProvider();
    assertFalse(rc.isEnabled());
  }

  @Test
  void resolvConf() {
    ResolvConfResolverConfigProvider rc =
        new ResolvConfResolverConfigProvider() {
          @Override
          public void initialize() {
            try {
              try (InputStream in =
                  ResolverConfigTest.class.getResourceAsStream("/test_loaded_resolv.conf")) {
                parseResolvConf(in);
              }
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
          }
        };

    rc.initialize();
    assertEquals(1, rc.servers().size());
    assertEquals(new InetSocketAddress("192.168.1.1", 53), rc.servers().get(0));
    assertEquals(2, rc.searchPaths().size());
    assertFalse(rc.searchPaths().contains(Name.fromConstantString("domain.com.")));
    assertEquals(5, rc.ndots());
  }

  @Test
  void jndi() {
    JndiContextResolverConfigProvider rc = new JndiContextResolverConfigProvider();
    assertTrue(rc.isEnabled());
    rc.initialize();
  }

  @Test
  void sunJvm() throws InitializationException {
    SunJvmResolverConfigProvider rc = new SunJvmResolverConfigProvider();
    assertFalse(rc.isEnabled());
    rc.initialize();
  }

  @Test
  void sunJvmServersEqualsJndi() throws InitializationException {
    SunJvmResolverConfigProvider sun = new SunJvmResolverConfigProvider();
    sun.initialize();
    JndiContextResolverConfigProvider jndi = new JndiContextResolverConfigProvider();
    jndi.initialize();
    assertEquals(sun.servers(), jndi.servers());
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void windowsServersContainedInJndi() throws InitializationException {
    JndiContextResolverConfigProvider jndi = new JndiContextResolverConfigProvider();
    jndi.initialize();
    WindowsResolverConfigProvider win = new WindowsResolverConfigProvider();
    win.initialize();

    // the servers returned via Windows API must be in the JNDI list, but not necessarily the other
    // way round. Unless there IPv6 servers which are not in the registry and Java <= 15 does not
    // find.
    for (InetSocketAddress winServer : win.servers()) {
      assertTrue(
          jndi.servers().contains(winServer),
          winServer + " not found in JNDI, " + win.servers() + "; " + jndi.servers());
    }
  }
}

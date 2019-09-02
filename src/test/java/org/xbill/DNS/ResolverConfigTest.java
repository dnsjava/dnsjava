package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

class ResolverConfigTest {

  @AfterEach
  void tearDown() {
    ResolverConfig.refresh();
  }

  @Test
  void findProperty_Success() {
    String[] dnsServers = {"server1", "server2"};
    // intentionally adding duplicate search entries for testing
    String[] dnsSearch = {"dnsjava.org", "example.com", "dnsjava.org"};
    Name[] searchPath =
        Arrays.stream(dnsSearch).map(s -> Name.fromConstantString(s + ".")).toArray(Name[]::new);
    System.setProperty(ResolverConfig.DNS_SERVER_PROP, String.join(",", dnsServers));
    System.setProperty(ResolverConfig.DNS_SEARCH_PROP, String.join(",", dnsSearch));
    try {
      ResolverConfig.refresh();
      ResolverConfig rc = ResolverConfig.getCurrentConfig();
      assertTrue(rc.findProperty());
      assertEquals("server1", rc.server());
      assertEquals(2, rc.servers().length);
      // any duplicate suffixes should be excluded
      assertEquals(2, rc.searchPath().length);
      assertEquals(searchPath[0], rc.searchPath()[0]);
      assertEquals(searchPath[1], rc.searchPath()[1]);
    } finally {
      System.clearProperty(ResolverConfig.DNS_SERVER_PROP);
      System.clearProperty(ResolverConfig.DNS_SEARCH_PROP);
    }
  }

  @Test
  @EnabledOnOs({OS.WINDOWS})
  void findNT_Windows() {
    assertTrue(ResolverConfig.getCurrentConfig().findWin());
  }

  @Test
  @DisabledOnOs({OS.WINDOWS})
  void findNT_NotWindows() {
    assertFalse(ResolverConfig.getCurrentConfig().findWin());
  }

  @Test
  @DisabledOnOs({OS.WINDOWS})
  void findUnix() {
    assertTrue(ResolverConfig.getCurrentConfig().findUnix());
  }

  @Test
  void resolvConfLoaded() {
    assertTrue(
        ResolverConfig.getCurrentConfig()
            .findResolvConf(
                ResolverConfigTest.class.getResourceAsStream("/test_loaded_resolv.conf")));
    assertEquals(5, ResolverConfig.getCurrentConfig().ndots());
  }

  @Test
  void findNetware() {
    assumeFalse(ResolverConfig.getCurrentConfig().findNetware());
  }

  @Test
  void findAndroid() {
    assumeFalse(ResolverConfig.getCurrentConfig().findAndroid());
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.xbill.DNS.config.PropertyResolverConfigProvider.DNS_NDOTS_PROP;
import static org.xbill.DNS.config.PropertyResolverConfigProvider.DNS_SEARCH_PROP;
import static org.xbill.DNS.config.PropertyResolverConfigProvider.DNS_SERVER_PROP;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
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
  @AfterEach
  void afterEach() throws Exception {
    // make sure the ResolverConfig providers are not staying initialized after a test
    Field configProvidersField = ResolverConfig.class.getDeclaredField("configProviders");
    configProvidersField.setAccessible(true);
    configProvidersField.set(null, null);
    Field currentConfigField = ResolverConfig.class.getDeclaredField("currentConfig");
    currentConfigField.setAccessible(true);
    currentConfigField.set(null, null);
  }

  @Test
  void testSkipInit() {
    try {
      System.setProperty(ResolverConfig.CONFIGPROVIDER_SKIP_INIT, Boolean.TRUE.toString());
      assertThat(ResolverConfig.getConfigProviders()).isEmpty();
    } finally {
      System.setProperty(ResolverConfig.CONFIGPROVIDER_SKIP_INIT, Boolean.FALSE.toString());
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
      assertThat(rc.isEnabled()).isTrue();
      rc.initialize();

      assertThat(rc.servers()).hasSize(2);
      assertThat(rc.servers().get(0).getAddress().getHostAddress()).isEqualTo(dnsServers1[0]);

      // must remove no longer present servers
      System.setProperty(DNS_SERVER_PROP, String.join(",", dnsServers2));
      rc.initialize();
      assertThat(rc.servers()).hasSize(1);

      // any duplicate suffixes should be excluded
      assertThat(rc.searchPaths()).hasSize(2);
      assertThat(rc.searchPaths().get(0)).isEqualTo(searchPath[0]);
      assertThat(rc.searchPaths().get(1)).isEqualTo(searchPath[1]);

      assertThat(rc.ndots()).isEqualTo(5);
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

      assertThat(rc.servers()).hasSize(5);
      assertThat(rc.servers().get(0).getAddress().getHostAddress()).isEqualTo("192.168.1.1");
      assertThat(rc.servers().get(0).getPort()).isEqualTo(SimpleResolver.DEFAULT_PORT);

      assertThat(rc.servers().get(1).getAddress().getHostAddress()).isEqualTo("192.168.1.1");
      assertThat(rc.servers().get(1).getPort()).isEqualTo(54);

      assertThat(rc.servers().get(2).getAddress().getHostAddress()).isEqualTo("0:0:0:0:0:0:0:1");
      assertThat(rc.servers().get(2).getPort()).isEqualTo(SimpleResolver.DEFAULT_PORT);

      assertThat(rc.servers().get(3).getAddress().getHostAddress()).isEqualTo("0:0:0:0:0:0:0:1");
      assertThat(rc.servers().get(3).getPort()).isEqualTo(54);

      assertThat(rc.servers().get(4).getAddress().getHostAddress()).isEqualTo("0:0:0:0:0:0:0:2");
      assertThat(rc.servers().get(4).getPort()).isEqualTo(53);
    } finally {
      System.clearProperty(DNS_SERVER_PROP);
    }
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void resolvConfDisabledOnWindows() {
    ResolvConfResolverConfigProvider rc = new ResolvConfResolverConfigProvider();
    assertThat(rc.isEnabled()).isFalse();
  }

  @Test
  @DisabledOnOs(OS.WINDOWS)
  void resolvConfEnabledOnUnix() {
    ResolvConfResolverConfigProvider rc = new ResolvConfResolverConfigProvider();
    assertThat(rc.isEnabled()).isTrue();
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void windowsEnabledOnWindows() {
    WindowsResolverConfigProvider rc = new WindowsResolverConfigProvider();
    assertThat(rc.isEnabled()).isTrue();
  }

  @Test
  @DisabledOnOs(OS.WINDOWS)
  void windowsDisabledOnUnix() {
    WindowsResolverConfigProvider rc = new WindowsResolverConfigProvider();
    assertThat(rc.isEnabled()).isFalse();
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
    assertThat(rc.servers()).hasSize(1);
    assertThat(rc.servers().get(0)).isEqualTo(new InetSocketAddress("192.168.1.1", 53));
    assertThat(rc.searchPaths()).hasSize(2);
    assertThat(rc.searchPaths()).doesNotContain(Name.fromConstantString("domain.com."));
    assertThat(rc.ndots()).isEqualTo(5);
  }

  @Test
  void jndi() {
    JndiContextResolverConfigProvider rc = new JndiContextResolverConfigProvider();
    assertThat(rc.isEnabled()).isTrue();
    rc.initialize();
  }

  @Test
  void sunJvm() throws InitializationException {
    SunJvmResolverConfigProvider rc = new SunJvmResolverConfigProvider();
    assertThat(rc.isEnabled()).isFalse();
    rc.initialize();
  }

  @Test
  void sunJvmServersEqualsJndi() throws InitializationException {
    SunJvmResolverConfigProvider sun = new SunJvmResolverConfigProvider();
    sun.initialize();
    JndiContextResolverConfigProvider jndi = new JndiContextResolverConfigProvider();
    jndi.initialize();
    assertThat(jndi.servers()).isEqualTo(sun.servers());
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void windowsServersContainedInJndi() throws InitializationException {
    JndiContextResolverConfigProvider jndi = new JndiContextResolverConfigProvider();
    jndi.initialize();
    WindowsResolverConfigProvider win = new WindowsResolverConfigProvider();
    win.initialize();

    // The servers returned via Windows API must be in the JNDI list, but not necessarily the other
    // way round. Unless there are IPv6 servers which are not in the registry and Java <= 15 does
    // not find.
    for (InetSocketAddress winServer : win.servers()) {
      assertThat(jndi.servers()).contains(winServer);
    }
  }

  @Test
  void refreshAsFirstCall() {
    assertDoesNotThrow(ResolverConfig::refresh);
  }
}

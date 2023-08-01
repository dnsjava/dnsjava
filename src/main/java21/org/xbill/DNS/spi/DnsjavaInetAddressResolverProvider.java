// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.spi;

import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;

public class DnsjavaInetAddressResolverProvider extends InetAddressResolverProvider {
  public static final String ENABLE_SPI = "org.dnsjava.spi.enable";

  @Override
  public InetAddressResolver get(Configuration configuration) {
    // The provider is opt-in only. Simply placing dnsjava on the classpath should not
    // modify default resolution behavior.
    if (Boolean.getBoolean(ENABLE_SPI)) {
      return new DnsjavaInetAddressResolver(configuration);
    }
    return configuration.builtinResolver();
  }

  @Override
  public String name() {
    return "dnsjava";
  }
}

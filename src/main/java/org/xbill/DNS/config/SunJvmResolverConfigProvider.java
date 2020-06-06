// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Resolver config provider that queries the traditional class {@code
 * sun.net.dns.ResolverConfiguration} via reflection.
 *
 * <p>As of Java 9, this generates an illegal reflective access exception and on Windows, this may
 * return invalid nameservers of disconnected NICs.
 */
public class SunJvmResolverConfigProvider extends BaseResolverConfigProvider {
  public void initialize() throws InitializationException {
    try {
      Class<?> resConfClass = Class.forName("sun.net.dns.ResolverConfiguration");
      Method open = resConfClass.getDeclaredMethod("open");
      Object resConf = open.invoke(null);

      Method nameserversMethod = resConfClass.getMethod("nameservers");
      @SuppressWarnings("unchecked")
      List<String> jvmNameservers = (List<String>) nameserversMethod.invoke(resConf);
      for (String ns : jvmNameservers) {
        addNameserver(new InetSocketAddress(ns, 53));
      }

      Method searchlistMethod = resConfClass.getMethod("searchlist");
      @SuppressWarnings("unchecked")
      List<String> jvmSearchlist = (List<String>) searchlistMethod.invoke(resConf);
      for (String n : jvmSearchlist) {
        addSearchPath(n);
      }
    } catch (Exception e) {
      throw new InitializationException(e);
    }
  }

  @Override
  public boolean isEnabled() {
    return Boolean.getBoolean("dnsjava.configprovider.sunjvm.enabled");
  }
}

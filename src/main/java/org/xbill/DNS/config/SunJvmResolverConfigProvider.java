// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.config;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Resolver config provider that queries the traditional class {@code
 * sun.net.dns.ResolverConfiguration} via reflection.
 *
 * <ul>
 *   <li>Java 9: generates an illegal reflective access exception.
 *   <li>Java 16 (classpath): requires adding the JVM flag {@code --add-opens
 *       java.base/sun.net.dns=ALL-UNNAMED}.
 *   <li>On Windows, may return invalid nameservers of disconnected NICs before Java 15, <a
 *       href="https://bugs.openjdk.java.net/browse/JDK-7006496">JDK-7006496</a>.
 * </ul>
 */
public class SunJvmResolverConfigProvider extends BaseResolverConfigProvider {
  @Override
  public void initialize() throws InitializationException {
    reset();
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

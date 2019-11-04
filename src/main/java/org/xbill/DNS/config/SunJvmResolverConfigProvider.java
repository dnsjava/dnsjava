// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import static java.util.stream.Collectors.toList;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import org.xbill.DNS.Name;

/**
 * Resolver config provider that queries the traditional class {@code
 * sun.net.dns.ResolverConfiguration} via reflection.
 *
 * <p>As of Java 9, this generates an illegal reflective access exception and on Windows, this may
 * return invalid nameservers of disconnected NICs.
 */
public class SunJvmResolverConfigProvider implements ResolverConfigProvider {
  private List<InetSocketAddress> nameservers = null;
  private List<Name> searchlist = null;

  public void initialize() throws InitializationException {
    try {
      Class<?> resConfClass = Class.forName("sun.net.dns.ResolverConfiguration");
      Method open = resConfClass.getDeclaredMethod("open");
      Object resConf = open.invoke(null);

      Method nameserversMethod = resConfClass.getMethod("nameservers");
      @SuppressWarnings("unchecked")
      List<String> jvmNameservers = (List<String>) nameserversMethod.invoke(resConf);
      nameservers =
          jvmNameservers.stream().map(ns -> new InetSocketAddress(ns, 53)).collect(toList());

      Method searchlistMethod = resConfClass.getMethod("searchlist");
      @SuppressWarnings("unchecked")
      List<String> jvmSearchlist = (List<String>) searchlistMethod.invoke(resConf);
      searchlist = jvmSearchlist.stream().map(Name::fromConstantString).collect(toList());
    } catch (Exception e) {
      throw new InitializationException(e);
    }
  }

  @Override
  public List<InetSocketAddress> servers() {
    if (nameservers == null) {
      throw new IllegalStateException("not initialized");
    }

    return Collections.unmodifiableList(nameservers);
  }

  @Override
  public List<Name> searchPaths() {
    if (searchlist == null) {
      throw new IllegalStateException("not initialized");
    }

    return Collections.unmodifiableList(searchlist);
  }

  @Override
  public boolean isEnabled() {
    return !System.getProperty("java.vendor").contains("Android");
  }
}

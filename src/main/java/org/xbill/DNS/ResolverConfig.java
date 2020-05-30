// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.config.AndroidResolverConfigProvider;
import org.xbill.DNS.config.FallbackPropertyResolverConfigProvider;
import org.xbill.DNS.config.InitializationException;
import org.xbill.DNS.config.JndiContextResolverConfigProvider;
import org.xbill.DNS.config.PropertyResolverConfigProvider;
import org.xbill.DNS.config.ResolvConfResolverConfigProvider;
import org.xbill.DNS.config.ResolverConfigProvider;
import org.xbill.DNS.config.SunJvmResolverConfigProvider;
import org.xbill.DNS.config.WindowsResolverConfigProvider;

/**
 * Locates name servers and the search path to be appended to unqualified names.
 *
 * <p>The following are attempted, in order, until one succeeds.
 *
 * <UL>
 *   <LI>dnsjava properties, see {@link org.xbill.DNS.config.PropertyResolverConfigProvider}
 *   <LI>On Unix, /etc/resolv.conf is parsed, see {@link
 *       org.xbill.DNS.config.ResolvConfResolverConfigProvider}
 *   <LI>On Windows, GetAdaptersAddresses is called, see {@link
 *       org.xbill.DNS.config.WindowsResolverConfigProvider}
 *   <li>On Android, system properties or the ConnectivityManager are read, see {@link
 *       org.xbill.DNS.config.AndroidResolverConfigProvider}
 *   <li>The JNDI DNS Service Provider is queried, see {@link
 *       org.xbill.DNS.config.JndiContextResolverConfigProvider}
 *   <LI>The sun.net.dns.ResolverConfiguration class is queried, see {@link
 *       org.xbill.DNS.config.SunJvmResolverConfigProvider}
 *   <LI>"localhost" is used as the nameserver, and the search path is empty.
 * </UL>
 *
 * These routines will be called internally when creating Resolvers/Lookups without explicitly
 * specifying server names, and can also be called directly if desired.
 */
@Slf4j
public final class ResolverConfig {
  /** @since 3.2 */
  public static final String CONFIGPROVIDER_SKIP_INIT = "dnsjava.configprovider.skipinit";

  private final List<InetSocketAddress> servers = new ArrayList<>(2);
  private final List<Name> searchlist = new ArrayList<>(0);
  private int ndots = 1;

  private static ResolverConfig currentConfig;
  private static List<ResolverConfigProvider> configProviders;

  private static void checkInitialized() {
    if (configProviders == null) {
      configProviders = new ArrayList<>(8);
      if (!Boolean.getBoolean(CONFIGPROVIDER_SKIP_INIT)) {
        configProviders.add(new PropertyResolverConfigProvider());
        configProviders.add(new ResolvConfResolverConfigProvider());
        configProviders.add(new WindowsResolverConfigProvider());
        configProviders.add(new AndroidResolverConfigProvider());
        configProviders.add(new JndiContextResolverConfigProvider());
        configProviders.add(new SunJvmResolverConfigProvider());
        configProviders.add(new FallbackPropertyResolverConfigProvider());
      }
    }

    if (currentConfig == null) {
      refresh();
    }
  }

  /** Gets the current configuration */
  public static synchronized ResolverConfig getCurrentConfig() {
    checkInitialized();
    return currentConfig;
  }

  /**
   * Gets the ordered list of resolver config providers.
   *
   * @since 3.2
   */
  public static synchronized List<ResolverConfigProvider> getConfigProviders() {
    checkInitialized();
    return Collections.unmodifiableList(configProviders);
  }

  /** Set a new ordered list of resolver config providers. */
  public static synchronized void setConfigProviders(List<ResolverConfigProvider> providers) {
    configProviders = new ArrayList<>(providers);
  }

  /** Gets the current configuration */
  public static void refresh() {
    ResolverConfig newConfig = new ResolverConfig();
    synchronized (ResolverConfig.class) {
      currentConfig = newConfig;
    }
  }

  public ResolverConfig() {
    for (ResolverConfigProvider provider : configProviders) {
      if (provider.isEnabled()) {
        try {
          provider.initialize();
          if (servers.isEmpty()) {
            servers.addAll(provider.servers());
          }

          if (searchlist.isEmpty()) {
            List<Name> lsearchPaths = provider.searchPaths();
            if (!lsearchPaths.isEmpty()) {
              searchlist.addAll(lsearchPaths);
              ndots = provider.ndots();
            }
          }

          if (!servers.isEmpty() && !searchlist.isEmpty()) {
            // found both servers and search path, we're done
            return;
          }
        } catch (InitializationException e) {
          log.warn("Failed to initialize provider", e);
        }
      }
    }

    if (servers.isEmpty()) {
      servers.add(
          new InetSocketAddress(InetAddress.getLoopbackAddress(), SimpleResolver.DEFAULT_PORT));
    }
  }

  /** Returns all located servers */
  public List<InetSocketAddress> servers() {
    return servers;
  }

  /** Returns the first located server */
  public InetSocketAddress server() {
    return servers.get(0);
  }

  /** Returns all entries in the located search path */
  public List<Name> searchPath() {
    return searchlist;
  }

  /**
   * Gets the threshold for the number of dots which must appear in a name before it is considered
   * absolute. The default is {@code 1}, meaning meaning that if there are any dots in a name, the
   * name will be tried first as an absolute name.
   *
   * <p>Note that ndots can only be configured in a resolv.conf file or the property {@link
   * PropertyResolverConfigProvider#DNS_NDOTS_PROP}.
   */
  public int ndots() {
    return ndots;
  }
}

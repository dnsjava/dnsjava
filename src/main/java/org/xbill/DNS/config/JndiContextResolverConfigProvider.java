// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Hashtable;
import java.util.List;
import java.util.StringTokenizer;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Name;
import org.xbill.DNS.SimpleResolver;

/**
 * Resolver config provider that tries to extract the system's DNS servers from the <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-dns.html">JNDI DNS Service
 * Provider</a>.
 */
@Slf4j
public class JndiContextResolverConfigProvider implements ResolverConfigProvider {
  private InnerJndiContextResolverConfigProvider inner;

  public JndiContextResolverConfigProvider() {
    if (!System.getProperty("java.vendor").contains("Android")) {
      try {
        inner = new InnerJndiContextResolverConfigProvider();
      } catch (NoClassDefFoundError e) {
        log.debug("JNDI DNS not available");
      }
    }
  }

  @Slf4j
  private static final class InnerJndiContextResolverConfigProvider
      extends BaseResolverConfigProvider {
    static {
      log.debug("JNDI class: {}", DirContext.class.getName());
    }

    public void initialize() {
      Hashtable<String, String> env = new Hashtable<>();
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
      // http://mail.openjdk.java.net/pipermail/net-dev/2017-March/010695.html
      env.put("java.naming.provider.url", "dns://");

      String servers = null;
      try {
        DirContext ctx = new InitialDirContext(env);
        servers = (String) ctx.getEnvironment().get("java.naming.provider.url");
        ctx.close();
      } catch (NamingException e) {
        // ignore
      }

      if (servers != null) {
        StringTokenizer st = new StringTokenizer(servers, " ");
        while (st.hasMoreTokens()) {
          String server = st.nextToken();
          try {
            URI serverUri = new URI(server);
            String host = serverUri.getHost();
            if (host == null || host.isEmpty()) {
              // skip the fallback server to localhost
              continue;
            }

            int port = serverUri.getPort();
            if (port == -1) {
              port = SimpleResolver.DEFAULT_PORT;
            }

            addNameserver(new InetSocketAddress(host, port));
          } catch (URISyntaxException e) {
            log.debug("Could not parse {} as a dns server, ignoring", server, e);
          }
        }
      }
    }
  }

  @Override
  public void initialize() {
    inner.initialize();
  }

  @Override
  public List<InetSocketAddress> servers() {
    return inner.servers();
  }

  @Override
  public List<Name> searchPaths() {
    return inner.searchPaths();
  }

  @Override
  public boolean isEnabled() {
    return inner != null;
  }
}

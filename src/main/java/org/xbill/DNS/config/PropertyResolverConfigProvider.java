// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.StringTokenizer;
import org.xbill.DNS.SimpleResolver;

/**
 * The properties {@link #DNS_SERVER_PROP}, {@link #DNS_SEARCH_PROP} (comma delimited lists) are
 * checked. The servers can either be IP addresses or hostnames (which are resolved using Java's
 * built in DNS support).
 */
public class PropertyResolverConfigProvider extends BaseResolverConfigProvider {
  public static final String DNS_SERVER_PROP = "dns.server";
  public static final String DNS_SEARCH_PROP = "dns.search";
  public static final String DNS_NDOTS_PROP = "dns.ndots";

  private int ndots;

  @Override
  public void initialize() {
    String servers = System.getProperty(DNS_SERVER_PROP);
    if (servers != null) {
      StringTokenizer st = new StringTokenizer(servers, ",");
      while (st.hasMoreTokens()) {
        String server = st.nextToken();
        try {
          URI uri = new URI("dns://" + server);
          // assume this is an IPv6 address without brackets
          if (uri.getHost() == null) {
            addNameserver(new InetSocketAddress(server, SimpleResolver.DEFAULT_PORT));
          } else {
            int port = uri.getPort();
            if (port == -1) {
              port = SimpleResolver.DEFAULT_PORT;
            }

            addNameserver(new InetSocketAddress(uri.getHost(), port));
          }
        } catch (URISyntaxException e) {
          log.warn("Ignored invalid server {}", server);
        }
      }
    }

    String searchPathProperty = System.getProperty(DNS_SEARCH_PROP);
    parseSearchPathList(searchPathProperty, ",");

    String ndotsProperty = System.getProperty(DNS_NDOTS_PROP);
    ndots = parseNdots(ndotsProperty);
  }

  @Override
  public int ndots() {
    return ndots;
  }
}

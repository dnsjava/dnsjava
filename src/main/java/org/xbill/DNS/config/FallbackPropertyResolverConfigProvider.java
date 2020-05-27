// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

/**
 * The properties {@link #DNS_FALLBACK_SERVER_PROP}, {@link #DNS_FALLBACK_SEARCH_PROP} (comma
 * delimited lists) are checked. The servers can either be IP addresses or hostnames (which are
 * resolved using Java's built in DNS support).
 *
 * @since 3.2
 */
public class FallbackPropertyResolverConfigProvider extends PropertyResolverConfigProvider {
  public static final String DNS_FALLBACK_SERVER_PROP = "dns.fallback.server";
  public static final String DNS_FALLBACK_SEARCH_PROP = "dns.fallback.search";
  public static final String DNS_FALLBACK_NDOTS_PROP = "dns.fallback.ndots";

  @Override
  public void initialize() {
    initialize(DNS_FALLBACK_SERVER_PROP, DNS_FALLBACK_SEARCH_PROP, DNS_FALLBACK_NDOTS_PROP);
  }
}

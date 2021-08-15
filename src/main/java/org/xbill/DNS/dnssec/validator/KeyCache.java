// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec.validator;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

/**
 * Cache for DNSKEY RRsets or corresponding null/bad key entries with a limited size and respect for
 * TTL values.
 *
 * @since 3.5
 */
final class KeyCache {
  /** Name of the property that configures the maximum cache TTL. */
  public static final String MAX_TTL_CONFIG = "dnsjava.dnssec.keycache.max_ttl";

  /** Name of the property that configures the maximum cache size. */
  public static final String MAX_CACHE_SIZE_CONFIG = "dnsjava.dnssec.keycache.max_size";

  private static final int DEFAULT_MAX_TTL = 900;
  private static final int DEFAULT_MAX_CACHE_SIZE = 1000;

  /** This is the main caching data structure. */
  private final Map<String, CacheEntry> cache;

  private final Clock clock;

  /** This is the maximum TTL [s] that all key cache entries will have. */
  private long maxTtl = DEFAULT_MAX_TTL;

  /** This is the maximum number of entries that the key cache will hold. */
  private int maxCacheSize = DEFAULT_MAX_CACHE_SIZE;

  /** Creates a new instance of this class. Uses the default system clock for cache eviction. */
  public KeyCache() {
    this(Clock.systemUTC());
  }

  /**
   * Creates a new instance of this class.
   *
   * @param clock The clock to use for cache eviction.
   */
  public KeyCache(Clock clock) {
    this.clock = clock;
    this.cache =
        Collections.synchronizedMap(
            new LinkedHashMap<String, CacheEntry>() {
              @Override
              protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
                return size() >= KeyCache.this.maxCacheSize;
              }
            });
  }

  /**
   * Initialize the cache. This implementation recognizes the following configuration parameters:
   *
   * <dl>
   *   <dt>dnsjava.dnssec.keycache.max_ttl
   *   <dd>The maximum TTL to apply to any cache entry.
   *   <dt>dnsjava.dnssec.keycache.max_size
   *   <dd>The maximum number of entries that the cache will hold.
   * </dl>
   *
   * @param config The configuration information.
   */
  public void init(Properties config) {
    if (config == null) {
      return;
    }

    String s = config.getProperty(MAX_TTL_CONFIG);
    if (s != null) {
      this.maxTtl = Long.parseLong(s);
    }

    s = config.getProperty(MAX_CACHE_SIZE_CONFIG);
    if (s != null) {
      this.maxCacheSize = Integer.parseInt(s);
    }
  }

  /**
   * Find the 'closest' trusted DNSKEY rrset to the given name.
   *
   * @param n The name to start the search.
   * @param dclass The class this DNSKEY rrset should be in.
   * @return The 'closest' entry to 'n' in the same class as 'dclass'.
   */
  public KeyEntry find(Name n, int dclass) {
    while (n.labels() > 0) {
      String k = this.key(n, dclass);
      KeyEntry entry = this.lookupEntry(k);
      if (entry != null) {
        return entry;
      }

      n = new Name(n, 1);
    }

    return null;
  }

  /**
   * Store a {@link KeyEntry} in the cache. The entry will be ignored if it isn't a DNSKEY rrset, if
   * it doesn't have the SECURE security status, or if it isn't a null-Key.
   *
   * @param ke The key entry to cache.
   */
  public void store(KeyEntry ke) {
    if (!ke.isGood() && !ke.isNull()) {
      return;
    }

    if (ke.getType() != Type.DNSKEY) {
      return;
    }

    String k = this.key(ke.getName(), ke.getDClass());
    CacheEntry ce = new CacheEntry(ke, this.maxTtl);
    this.cache.put(k, ce);
  }

  private String key(Name n, int dclass) {
    return "K" + dclass + "/" + n;
  }

  private KeyEntry lookupEntry(String key) {
    CacheEntry centry = this.cache.get(key);
    if (centry == null) {
      return null;
    }

    if (centry.expiration.isBefore(clock.instant())) {
      this.cache.remove(key);
      return null;
    }

    return centry.keyEntry;
  }

  /** Utility class to cache key entries with an expiration date. */
  private class CacheEntry {
    private final Instant expiration;
    private final KeyEntry keyEntry;

    CacheEntry(KeyEntry keyEntry, long maxTtl) {
      long ttl = keyEntry.getTTL();
      if (ttl > maxTtl) {
        ttl = maxTtl;
      }

      this.expiration = clock.instant().plus(ttl, ChronoUnit.SECONDS);
      this.keyEntry = keyEntry;
    }
  }
}

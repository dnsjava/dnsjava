// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.util.Collection;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;

/**
 * Storage for DS or DNSKEY records that are known to be trusted.
 *
 * @since 3.6
 */
public interface TrustAnchorStore {
  /**
   * Stores the given {@link RRset} as known trusted keys.
   *
   * @param rrset The key set to store as trusted.
   */
  void store(RRset rrset);

  /**
   * Gets the closest trusted key for the given name or {@code null} if no match is found.
   *
   * @param name The name to search for.
   * @param dclass The {@link DClass} of the keys.
   * @return The closest found key for {@code name} or {@code null}.
   */
  RRset find(Name name, int dclass);

  /** Removes all stored trust anchors. */
  void clear();

  /** Gets all trust anchors currently in use. */
  Collection<RRset> items();
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec.validator;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.SRRset;
import org.xbill.DNS.dnssec.SecurityStatus;

/**
 * Storage for DS or DNSKEY records that are known to be trusted.
 *
 * @since 3.5
 */
public final class TrustAnchorStore {
  private final Map<String, SRRset> map;

  /** Creates a new instance of this class. */
  public TrustAnchorStore() {
    this.map = new HashMap<>();
  }

  /**
   * Stores the given RRset as known trusted keys. Existing keys for the same name and class are
   * overwritten.
   *
   * @param rrset The key set to store as trusted.
   */
  public void store(SRRset rrset) {
    if (rrset.getType() != Type.DS && rrset.getType() != Type.DNSKEY) {
      throw new IllegalArgumentException("Trust anchors can only be DS or DNSKEY records");
    }

    if (rrset.getType() == Type.DNSKEY) {
      SRRset temp = new SRRset();
      for (Record r : rrset.rrs()) {
        DNSKEYRecord key = (DNSKEYRecord) r;
        DSRecord ds =
            new DSRecord(key.getName(), key.getDClass(), key.getTTL(), DNSSEC.Digest.SHA384, key);
        temp.addRR(ds);
      }

      rrset = temp;
    }

    String k = this.key(rrset.getName(), rrset.getDClass());
    rrset.setSecurityStatus(SecurityStatus.SECURE);
    SRRset previous = this.map.put(k, rrset);
    if (previous != null) {
      previous.rrs().forEach(rrset::addRR);
    }
  }

  /**
   * Gets the closest trusted key for the given name or <code>null</code> if no match is found.
   *
   * @param name The name to search for.
   * @param dclass The class of the keys.
   * @return The closest found key for <code>name</code> or <code>null</code>.
   */
  public SRRset find(Name name, int dclass) {
    while (name.labels() > 0) {
      String k = this.key(name, dclass);
      SRRset r = this.lookup(k);
      if (r != null) {
        return r;
      }

      name = new Name(name, 1);
    }

    return null;
  }

  /** Removes all stored trust anchors. */
  public void clear() {
    this.map.clear();
  }

  /** Gets all trust anchors currently in use. */
  public Collection<SRRset> items() {
    return Collections.unmodifiableCollection(this.map.values());
  }

  private SRRset lookup(String key) {
    return this.map.get(key);
  }

  private String key(Name n, int dclass) {
    return "T" + dclass + "/" + n.canonicalize();
  }
}

// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.security.PublicKey;

/**
 * Child DNSKEY record as specified in RFC 8078.
 *
 * @see DNSSEC
 * @see <a href="https://tools.ietf.org/html/rfc8078">RFC 8078: Managing DS Records from the Parent
 *     via CDS/CDNSKEY</a>
 */
public class CDNSKEYRecord extends DNSKEYRecord {
  CDNSKEYRecord() {}

  /**
   * Creates a CDNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key Binary representation of the key
   */
  public CDNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
    super(name, Type.CDNSKEY, dclass, ttl, flags, proto, alg, key);
  }

  /**
   * Creates a CDNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key The key as a PublicKey
   * @throws DNSSEC.DNSSECException The PublicKey could not be converted into DNS format.
   */
  public CDNSKEYRecord(
      Name name, int dclass, long ttl, int flags, int proto, int alg, PublicKey key)
      throws DNSSEC.DNSSECException {
    super(name, Type.CDNSKEY, dclass, ttl, flags, proto, alg, DNSSEC.fromPublicKey(key, alg));
  }
}

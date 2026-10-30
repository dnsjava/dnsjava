// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.security.PublicKey;

/**
 * Key - contains a cryptographic public key for use by DNS. The data can be converted to objects
 * implementing java.security.interfaces.PublicKey
 *
 * @see DNSSEC
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4034">RFC 4034: Resource Records for the
 *     DNS Security Extensions</a>
 */
public class DNSKEYRecord extends KEYBase {

  public static class Protocol {
    private Protocol() {}

    /** Key will be used for DNSSEC */
    public static final int DNSSEC = 3;
  }

  /**
   * {@code DNSKEY} flags as defined in the <a
   * href="https://www.iana.org/assignments/dnskey-flags/dnskey-flags.xhtml">IANA registry</a>.
   */
  public static class Flags {
    private Flags() {}

    /**
     * Key is a zone key. Flags bit 7.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc3757">RFC 3757</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4034">RFC 4034</a>
     */
    public static final int ZONE_KEY = 0b0000_0001_0000_0000;

    /**
     * Key has been revoked. Flags bit 8.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc5011">RFC 5011</a>
     */
    public static final int REVOKE = 0b0000_0000_1000_0000;

    /**
     * Authoritative Delegation Types. Flags bit 14.
     *
     * @since 3.7.0
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-delext-12">draft-ietf-dnsop-delext-12</a>
     */
    public static final int AUTHORITATIVE_DELEGATION_TYPES = 0b0000_0000_0000_0010;

    /**
     * Key is a secure entry point key. Flags bit 15.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc3757">RFC 3757</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4034">RFC 4034</a>
     */
    public static final int SEP_KEY = 0b0000_0000_0000_0001;
  }

  DNSKEYRecord() {}

  /**
   * Creates a DNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key Binary representation of the key
   */
  protected DNSKEYRecord(
      Name name, int type, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
    super(name, type, dclass, ttl, flags, proto, alg, key);
  }

  /**
   * Creates a DNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key Binary representation of the key
   */
  public DNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
    this(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, key);
  }

  /**
   * Creates a DNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key The key as a PublicKey
   * @throws DNSSEC.DNSSECException The PublicKey could not be converted into DNS format.
   */
  public DNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg, PublicKey key)
      throws DNSSEC.DNSSECException {
    super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, DNSSEC.fromPublicKey(key, alg));
    publicKey = key;
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    flags = st.getUInt16();
    proto = st.getUInt8();
    String algString = st.getString();
    alg = DNSSEC.Algorithm.value(algString);
    if (alg < 0) {
      throw st.exception("Invalid algorithm: " + algString);
    }
    key = st.getBase64();
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DNSSEC.UnsupportedAlgorithmException;
import org.xbill.DNS.IPSECKEYRecord.Algorithm;
import org.xbill.DNS.Tokenizer.Token;
import org.xbill.DNS.utils.base16;
import org.xbill.DNS.utils.base64;

/**
 * Host Identity Protocol (HIP) Record as defined in RFC 8005.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8005">RFC 8005: Host Identity Protocol
 *     (HIP) Domain Name System (DNS) Extension</a>
 * @see IPSECKEYRecord.Algorithm for PK algorithm numbers
 */
public class HIPRecord extends Record {
  private byte[] hit;
  private int pkAlgorithm;
  private byte[] publicKey;
  private final List<Name> rvServers = new ArrayList<>();

  HIPRecord() {}

  public HIPRecord(
      Name name, int dclass, long ttl, byte[] hit, int alg, byte[] key, List<Name> servers) {
    super(name, Type.HIP, dclass, ttl);
    if (hit == null || hit.length == 0) {
      throw new IllegalArgumentException("hit is required and must be non-empty");
    }
    if (key == null || key.length == 0) {
      throw new IllegalArgumentException("key is required and must be non-empty");
    }

    this.hit = hit;
    this.pkAlgorithm = alg;
    this.publicKey = key;
    if (servers != null) {
      this.rvServers.addAll(servers);
    }
  }

  public HIPRecord(Name name, int dclass, long ttl, byte[] hit, int alg, byte[] key) {
    this(name, dclass, ttl, hit, alg, key, null);
  }

  public HIPRecord(
      Name name, int dclass, long ttl, byte[] hit, int alg, PublicKey key, List<Name> servers)
      throws DNSSECException {
    this(name, dclass, ttl, hit, alg, DNSSEC.fromPublicKey(key, mapAlgTypeToDnssec(alg)), servers);
  }

  public HIPRecord(Name name, int dclass, long ttl, byte[] hit, int alg, PublicKey key)
      throws DNSSECException {
    this(name, dclass, ttl, hit, alg, key, null);
  }

  public byte[] getHit() {
    return hit;
  }

  /**
   * Gets the PK algorithm number as defined in <a
   * href="https://www.iana.org/assignments/ipseckey-rr-parameters/ipseckey-rr-parameters.xhtml#ipseckey-rr-parameters-1">IPSECKEY
   * Resource Record Parameters</a>
   *
   * @see IPSECKEYRecord.Algorithm
   */
  public int getAlgorithm() {
    return pkAlgorithm;
  }

  /** Gets the raw public key bytes. The format is defined by {@link #getAlgorithm()}. */
  public byte[] getKey() {
    return publicKey;
  }

  /**
   * Gets the public key of this RR as a Java {@link PublicKey}. Only supported for RSA/DSA PK
   * algorithm (ECDSA lacks the information about which curve is used).
   */
  public PublicKey getPublicKey() throws DNSSECException {
    return DNSSEC.toPublicKey(mapAlgTypeToDnssec(pkAlgorithm), publicKey, this);
  }

  public List<Name> getRvServers() {
    return Collections.unmodifiableList(rvServers);
  }

  private static int mapAlgTypeToDnssec(int alg) throws UnsupportedAlgorithmException {
    switch (alg) {
      case Algorithm.DSA:
        return DNSSEC.Algorithm.DSA;
      case Algorithm.RSA:
        return DNSSEC.Algorithm.RSASHA1;
      case Algorithm.ECDSA:
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    if (Options.multiline()) {
      sb.append("( ");
    }

    String separator = Options.multiline() ? "\n\t" : " ";
    sb.append(pkAlgorithm);
    sb.append(" ");
    sb.append(base16.toString(hit));
    sb.append(separator);

    sb.append(base64.toString(publicKey));
    if (!rvServers.isEmpty()) {
      sb.append(separator);
    }

    sb.append(rvServers.stream().map(Name::toString).collect(Collectors.joining(separator)));
    if (Options.multiline()) {
      sb.append(" )");
    }

    return sb.toString();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    pkAlgorithm = st.getUInt8();
    hit = st.getHexString();
    if (hit == null || hit.length == 0) {
      throw st.exception("hit is required and must be non-empty");
    }

    String base64publicKey = st.getString();
    if (base64publicKey == null || base64publicKey.isEmpty()) {
      throw st.exception("public key is required and must be non-empty");
    }

    publicKey = base64.fromString(base64publicKey);
    Token t;
    while ((t = st.get()).isString()) {
      rvServers.add(Name.fromString(t.value(), origin));
    }
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(hit.length);
    out.writeU8(pkAlgorithm);
    out.writeU16(publicKey.length);
    out.writeByteArray(hit);
    out.writeByteArray(publicKey);
    for (Name n : rvServers) {
      n.toWire(out, null, canonical);
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    int hitLength = in.readU8();
    pkAlgorithm = in.readU8();
    int pkLength = in.readU16();
    hit = in.readByteArray(hitLength);
    if (hit == null || hit.length == 0) {
      throw new WireParseException("hit is required and must be non-empty");
    }
    publicKey = in.readByteArray(pkLength);
    if (publicKey == null || publicKey.length == 0) {
      throw new WireParseException("public key is required and must be non-empty");
    }
    while (in.remaining() > 0) {
      rvServers.add(new Name(in));
    }
  }
}

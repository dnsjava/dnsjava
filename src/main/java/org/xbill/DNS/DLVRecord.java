// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2002-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import org.xbill.DNS.utils.base16;

/**
 * DLV - contains a Delegation Lookaside Validation record, which acts as the equivalent of a DS
 * record in a lookaside zone.
 *
 * @see DNSSEC
 * @see DSRecord
 * @author David Blacka
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4431">RFC 4431: The DNSSEC Lookaside
 *     Validation (DLV) DNS Resource Record</a>
 */
public class DLVRecord extends Record {

  /**
   * SHA1 digest ID for DLV records.
   *
   * @deprecated use {@link DNSSEC.Digest#SHA1}
   */
  @Deprecated public static final int SHA1_DIGEST_ID = DNSSEC.Digest.SHA1;

  /**
   * SHA256 digest ID for DLV records.
   *
   * @deprecated use {@link DNSSEC.Digest#SHA256}
   */
  @Deprecated public static final int SHA256_DIGEST_ID = DNSSEC.Digest.SHA256;

  private int footprint;
  private int alg;
  private int digestid;
  private byte[] digest;

  DLVRecord() {}

  /**
   * Creates a DLV Record from the given data
   *
   * @param footprint The original KEY record's footprint (keyid).
   * @param alg The original key algorithm.
   * @param digestid The digest id code.
   * @param digest A hash of the original key.
   */
  public DLVRecord(
      Name name, int dclass, long ttl, int footprint, int alg, int digestid, byte[] digest) {
    super(name, Type.DLV, dclass, ttl);
    this.footprint = checkU16("footprint", footprint);
    this.alg = checkU8("alg", alg);
    this.digestid = checkU8("digestid", digestid);
    this.digest = digest;
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    footprint = in.readU16();
    alg = in.readU8();
    digestid = in.readU8();
    digest = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    footprint = st.getUInt16();
    alg = st.getUInt8();
    digestid = st.getUInt8();
    digest = st.getHex(true);
  }

  /** Converts rdata to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(footprint);
    sb.append(" ");
    sb.append(alg);
    sb.append(" ");
    sb.append(digestid);
    if (digest != null) {
      sb.append(" ");
      sb.append(base16.toString(digest));
    }

    return sb.toString();
  }

  /** Returns the key's algorithm. */
  public int getAlgorithm() {
    return alg;
  }

  /** Returns the key's Digest ID. */
  public int getDigestID() {
    return digestid;
  }

  /** Returns the binary hash of the key. */
  public byte[] getDigest() {
    return digest;
  }

  /** Returns the key's footprint. */
  public int getFootprint() {
    return footprint;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(footprint);
    out.writeU8(alg);
    out.writeU8(digestid);
    if (digest != null) {
      out.writeByteArray(digest);
    }
  }
}

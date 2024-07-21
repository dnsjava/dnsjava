// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * Certification Authority Authorization
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6844">RFC 6844: DNS Certification
 *     Authority Authorization (CAA) Resource Record</a>
 */
public class CAARecord extends Record {
  public static class Flags {
    private Flags() {}

    public static final int IssuerCritical = 128;
  }

  private int flags;
  private byte[] tag;
  private byte[] value;

  CAARecord() {}

  /**
   * Creates an CAA Record from the given data.
   *
   * @param flags The flags.
   * @param tag The tag.
   * @param value The value.
   */
  public CAARecord(Name name, int dclass, long ttl, int flags, String tag, String value) {
    super(name, Type.CAA, dclass, ttl);
    this.flags = checkU8("flags", flags);
    try {
      this.tag = byteArrayFromString(tag);
      this.value = byteArrayFromString(value);
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    flags = in.readU8();
    tag = in.readCountedString();
    value = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    flags = st.getUInt8();
    try {
      tag = byteArrayFromString(st.getString());
      value = byteArrayFromString(st.getString());
    } catch (TextParseException e) {
      throw st.exception(e.getMessage());
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(flags);
    sb.append(" ");
    sb.append(byteArrayToString(tag, false));
    sb.append(" ");
    sb.append(byteArrayToString(value, true));
    return sb.toString();
  }

  /** Returns the flags. */
  public int getFlags() {
    return flags;
  }

  /** Returns the tag. */
  public String getTag() {
    return byteArrayToString(tag, false);
  }

  /** Returns the value */
  public String getValue() {
    return byteArrayToString(value, false);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(flags);
    out.writeCountedString(tag);
    out.writeByteArray(value);
  }
}

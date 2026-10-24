// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

/**
 * Certification Authority Authorization
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659">RFC 8659: DNS Certification
 *     Authority Authorization (CAA) Resource Record</a>
 */
public class CAARecord extends Record {
  public static class Flags {
    private Flags() {}

    public static final int IssuerCritical = 128;
  }

  /**
   * Know tag values in IANA registry Public Key Infrastructure using X.509 (PKIX) Parameters,
   * Certification Authority Restriction Properties.
   *
   * @see <a href="https://www.iana.org/assignments/pkix-parameters">Public Key Infrastructure using
   *     X.509 (PKIX) Parameters</a>
   */
  public static class Tags {
    /**
     * Authorization Entry by Domain.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-7.2">RFC 8659, Section
     *     7.2</a>
     */
    public static final String ISSUE = "issue";

    /**
     * Authorization Entry by Wildcard Domain.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-7.2">RFC 8659, Section
     *     7.2</a>
     */
    public static final String ISSUEWILD = "issuewild";

    /**
     * Report incident by IODEF report.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-7.2">RFC 8659, Section
     *     7.2</a>
     */
    public static final String IODEF = "iodef";

    /**
     * Reserved in RFC 8659.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-7.2">RFC 8659, Section
     *     7.2</a>
     */
    public static final String AUTH = "auth";

    /**
     * Reserved in RFC 8659; Authorization Entry by Signature Path in
     * draft-hallambaker-donotissue-04.
     *
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/draft-hallambaker-donotissue-04#rfc.section.5.2">draft-hallambaker-donotissue-04,
     *     Section 5.2</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-7.2">RFC 8659, Section
     *     7.2</a>
     */
    public static final String PATH = "path";

    /**
     * Reserved in RFC 8659; Authorization Entry by Certificate Policy in
     * draft-hallambaker-donotissue-04.
     *
     * @see <a
     *     href="https://datatracker.ietf.org/doc/html/draft-hallambaker-donotissue-04#rfc.section.5.2">draft-hallambaker-donotissue-04,
     *     Section 5.2</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8659#section-7.2">RFC 8659, Section
     *     7.2</a>
     */
    public static final String POLICY = "policy";

    /**
     * Authorized e-mail contact for domain validation.
     *
     * @see <a
     *     href="https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.6.3.pdf">CA/Browser
     *     Forum 1.6.3</a>
     * @see <a href="https://cabforum.org/">CA/Browser Forum</a>
     */
    public static final String CONTACTEMAIL = "contactemail";

    /**
     * Authorized phone contact for DNS validation.
     *
     * @see <a href="https://cabforum.org/pipermail/public/2019-January/014498.html">CA/Browser
     *     Forum Ballot SC14</a>
     * @see <a href="https://cabforum.org/">CA/Browser Forum</a>
     */
    public static final String CONTACTPHONE = "contactphone";

    /**
     * Authorization Entry by Domain for Verified Mark Certificates.
     *
     * @see <a href="https://bimigroup.org/resources/VMC_Guidelines_latest.pdf">VMC Requirements
     *     v1.0</a>
     * @see <a href="mailto:corey.bonnell@digicert.com">Corey Bonnell</a>
     */
    public static final String ISSUEVMC = "issuevmc";

    /**
     * Authorization Entry by Email Address.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9495">RFC 9495</a>
     */
    public static final String ISSUEMAIL = "issuemail";
  }

  private int flags;
  private String tag;
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
    this.tag = validateTag(IllegalArgumentException::new, tag);

    try {
      this.value = byteArrayFromString(value, -1);
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }
  }

  private static <T extends Throwable> String validateTag(
      Function<String, T> getException, String tag) throws T {
    if (tag == null || tag.isEmpty() || tag.length() > 255) {
      throw getException.apply("invalid tag");
    }
    for (int i = 0; i < tag.length(); i++) {
      char c = tag.charAt(i);
      if ((c < '0' || c > '9') && (c < 'a' || c > 'z')) {
        throw getException.apply("invalid tag; must be ASCII letters and numbers in lowercase");
      }
    }

    return tag;
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    flags = in.readU8();
    tag = validateTag(WireParseException::new, byteArrayToString(in.readCountedString(), false));
    value = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    flags = st.getUInt8();

    try {
      tag = validateTag(TextParseException::new, st.getString());
      value = byteArrayFromString(st.getString(), -1);
    } catch (TextParseException | IllegalArgumentException e) {
      throw st.exception(e.getMessage());
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(flags);
    sb.append(" ");
    sb.append(tag);
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
    return tag;
  }

  /**
   * Returns the value as a string.
   *
   * @param escape if true, returns the RR textual representation of the underlying bytes. If false,
   *     returns just the simple string using the UTF-8 charset with no additional escaping.
   * @since 3.6.5
   */
  public String getValue(boolean escape) {
    return escape ? byteArrayToString(value, false) : new String(value, StandardCharsets.UTF_8);
  }

  /** Returns the value as a string, escaped for RR textual representation */
  public String getValue() {
    return getValue(true);
  }

  /**
   * Returns the value as a raw byte-array
   *
   * @since 3.6.5
   */
  public byte[] getValueAsByteArray() {
    return value;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(flags);
    out.writeCountedString(tag.getBytes(StandardCharsets.US_ASCII));
    out.writeByteArray(value);
  }
}

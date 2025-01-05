// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import lombok.experimental.UtilityClass;
import org.xbill.DNS.utils.base16;

/**
 * ZONEMD Resource record.
 *
 * @since 3.6
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8976">RFC 8976</a>
 */
public class ZoneMDRecord extends Record {
  /**
   * ZONEMD Schemes.
   *
   * @see <a
   *     href="https://www.iana.org/assignments/dns-parameters/dns-parameters.xml#zonemd-schemes">IANA
   *     registry</a>
   */
  @UtilityClass
  public static class Scheme {
    /** Reserved. */
    public static final int RESERVED = 0;

    /** Simple ZONEMD collation */
    public static final int SIMPLE = 1;

    private static final Mnemonic schemes = new Mnemonic("ZONEMD Schemes", Mnemonic.CASE_UPPER);

    static {
      schemes.setMaximum(0xFF);
      schemes.setNumericAllowed(true);
      schemes.add(RESERVED, "RESERVED");
      schemes.add(SIMPLE, "SIMPLE");
    }

    /** Converts an algorithm into its textual representation */
    public static String string(int alg) {
      return schemes.getText(alg);
    }

    /**
     * Converts a textual representation of a scheme into its numeric code. Integers in the range
     * 0..255 are also accepted.
     *
     * @param s The textual representation of the scheme.
     * @return The algorithm code, or -1 for an unknown scheme.
     */
    public static int value(String s) {
      return schemes.getValue(s);
    }
  }

  /**
   * ZONEMD Hash Algorithms.
   *
   * @see <a
   *     href="https://www.iana.org/assignments/dns-parameters/dns-parameters.xml#zonemd-hash-algorithms">IANA
   *     registry</a>
   */
  @UtilityClass
  public static class Hash {
    /** Reserved. */
    public static final int RESERVED = 0;

    /** SHA-384 */
    public static final int SHA384 = 1;

    /** SHA-512 */
    public static final int SHA512 = 2;

    private static final Mnemonic schemes =
        new Mnemonic("ZONEMD Hash Algorithms", Mnemonic.CASE_UPPER);
    private static final Map<Integer, Integer> hashLengths = new HashMap<>(2);

    static {
      schemes.setMaximum(0xFF);
      schemes.setNumericAllowed(true);
      schemes.add(RESERVED, "RESERVED");
      schemes.add(SHA384, "SHA384");
      hashLengths.put(SHA384, 48);
      schemes.add(SHA512, "SHA512");
      hashLengths.put(SHA512, 64);
    }

    /** Converts an algorithm into its textual representation */
    public static String string(int alg) {
      return schemes.getText(alg);
    }

    /**
     * Converts a textual representation of a hash algorithm into its numeric code. Integers in the
     * range 0..255 are also accepted.
     *
     * @param s The textual representation of the hash algorithm.
     * @return The algorithm code, or -1 for an unknown hash algorithm.
     */
    public static int value(String s) {
      return schemes.getValue(s);
    }

    /**
     * Gets the length, in bytes, of the specified hash algorithm.
     *
     * @return The length, in bytes, or -1 for an unknown hash algorithm.
     */
    public static int hashLength(int hashAlgorithm) {
      Integer len = hashLengths.get(hashAlgorithm);
      return len == null ? -1 : len;
    }
  }

  /**
   * A 32-bit unsigned integer in network byte order. It is the serial number from the zone's SOA
   * record (<a href="https://datatracker.ietf.org/doc/html/rfc1035">RFC 1035, Section 3.3.13]</a>)
   * for which the zone digest was generated.
   */
  @Getter private long serial;

  /**
   * An 8-bit unsigned integer that identifies the methods by which data is collated and presented
   * as input to the hashing function.
   *
   * @see Scheme
   */
  @Getter private int scheme;

  /**
   * An 8-bit unsigned integer that identifies the cryptographic hash algorithm used to construct
   * the digest.
   *
   * @see Hash
   */
  @Getter private int hashAlgorithm;

  /**
   * A byte array containing the output of the hash algorithm. The length is determined by {@link
   * #getHashAlgorithm()}.
   *
   * @see Hash
   */
  @Getter private byte[] digest;

  ZoneMDRecord() {}

  public ZoneMDRecord(
      Name name, int dclass, long ttl, long serial, int scheme, int hashAlgorithm, byte[] digest) {
    super(name, Type.ZONEMD, dclass, ttl);
    this.serial = checkU32("serial", serial);
    this.scheme = checkU8("scheme", scheme);
    this.hashAlgorithm = checkU8("hashAlgorithm", hashAlgorithm);
    String validateDigestSizeMessage = getDigestSizeExceptionMessage(hashAlgorithm, digest);
    if (validateDigestSizeMessage != null) {
      throw new IllegalArgumentException(validateDigestSizeMessage);
    }
    this.digest = digest;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU32(serial);
    out.writeU8(scheme);
    out.writeU8(hashAlgorithm);
    out.writeByteArray(digest);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    serial = in.readU32();
    scheme = in.readU8();
    hashAlgorithm = in.readU8();
    digest = in.readByteArray();
    String validateDigestSizeMessage = getDigestSizeExceptionMessage(hashAlgorithm, digest);
    if (validateDigestSizeMessage != null) {
      throw new WireParseException(validateDigestSizeMessage);
    }
  }

  @Override
  protected String rrToString() {
    String rr = serial + " " + scheme + " " + hashAlgorithm + " ";

    if (Options.multiline()) {
      rr += "(" + base16.toString(digest, 48, "\t", true);
    } else {
      rr += base16.toString(digest);
    }
    return rr;
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    serial = st.getUInt32();
    scheme = st.getUInt8();
    hashAlgorithm = st.getUInt8();
    digest = st.getHex(true);
    String validateDigestSizeMessage = getDigestSizeExceptionMessage(hashAlgorithm, digest);
    if (validateDigestSizeMessage != null) {
      throw st.exception(validateDigestSizeMessage);
    }
  }

  private String getDigestSizeExceptionMessage(int hashAlgorithm, byte[] digest) {
    int len = Hash.hashLength(hashAlgorithm);
    if (len != -1 && len != digest.length) {
      return "Digest size for "
          + Hash.string(hashAlgorithm)
          + " be exactly "
          + Hash.hashLength(hashAlgorithm)
          + " bytes, got "
          + digest.length;
    } else if (digest.length < 12) {
      return "Digest size must be at least 12 bytes, got " + digest.length;
    }

    return null;
  }
}

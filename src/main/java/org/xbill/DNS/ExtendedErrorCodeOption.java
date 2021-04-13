// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.Getter;

/**
 * EDNS option to provide additional information about the cause of DNS errors (RFC 8914).
 *
 * @since 3.4
 */
public class ExtendedErrorCodeOption extends EDNSOption {
  public static final int OTHER = 0;
  public static final int UNSUPPORTED_DNSKEY_ALGORITHM = 1;
  public static final int UNSUPPORTED_DS_DIGEST_TYPE = 2;
  public static final int STALE_ANSWER = 3;
  public static final int FORGED_ANSWER = 4;
  public static final int DNSSEC_INDETERMINATE = 5;
  public static final int DNSSEC_BOGUS = 6;
  public static final int SIGNATURE_EXPIRED = 7;
  public static final int SIGNATURE_NOT_YET_VALID = 8;
  public static final int DNSKEY_MISSING = 9;
  public static final int RRSIGS_MISSING = 10;
  public static final int NO_ZONE_KEY_BIT_SET = 11;
  public static final int NSEC_MISSING = 12;
  public static final int CACHED_ERROR = 13;
  public static final int NOT_READY = 14;
  public static final int BLOCKED = 15;
  public static final int CENSORED = 16;
  public static final int FILTERED = 17;
  public static final int PROHIBITED = 18;
  public static final int STALE_NXDOMAIN_ANSWER = 19;
  public static final int NOT_AUTHORITATIVE = 20;
  public static final int NOT_SUPPORTED = 21;
  public static final int NO_REACHABLE_AUTHORITY = 22;
  public static final int NETWORK_ERROR = 23;
  public static final int INVALID_DATA = 24;

  @Getter private int errorCode;
  @Getter private String text;

  private static final Mnemonic codes =
      new Mnemonic("EDNS Extended Error Codes", Mnemonic.CASE_SENSITIVE);

  static {
    codes.setMaximum(0xFFFF);
    codes.setPrefix("EDE");
    codes.add(OTHER, "Other");
    codes.add(UNSUPPORTED_DNSKEY_ALGORITHM, "Unsupported DNSKEY Algorithm");
    codes.add(UNSUPPORTED_DS_DIGEST_TYPE, "Unsupported DS Digest Type");
    codes.add(STALE_ANSWER, "Stale Answer");
    codes.add(FORGED_ANSWER, "Forged Answer");
    codes.add(DNSSEC_INDETERMINATE, "DNSSEC Indeterminate");
    codes.add(DNSSEC_BOGUS, "DNSSEC Bogus");
    codes.add(SIGNATURE_EXPIRED, "Signature Expired");
    codes.add(SIGNATURE_NOT_YET_VALID, "Signature Not Yet Valid");
    codes.add(DNSKEY_MISSING, "DNSKEY Missing");
    codes.add(RRSIGS_MISSING, "RRSIGs Missing");
    codes.add(NO_ZONE_KEY_BIT_SET, "No Zone Key Bit Set");
    codes.add(NSEC_MISSING, "NSEC Missing");
    codes.add(CACHED_ERROR, "Cached Error");
    codes.add(NOT_READY, "Not Ready");
    codes.add(BLOCKED, "Blocked");
    codes.add(CENSORED, "Censored");
    codes.add(FILTERED, "Filtered");
    codes.add(PROHIBITED, "Prohibited");
    codes.add(STALE_NXDOMAIN_ANSWER, "Stale NXDOMAIN Answer");
    codes.add(NOT_AUTHORITATIVE, "Not Authoritative");
    codes.add(NOT_SUPPORTED, "Not Supported");
    codes.add(NO_REACHABLE_AUTHORITY, "No Reachable Authority");
    codes.add(NETWORK_ERROR, "Network Error");
    codes.add(INVALID_DATA, "Invalid Data");
  }

  /** Creates an extended error code EDNS option. */
  ExtendedErrorCodeOption() {
    super(Code.EDNS_EXTENDED_ERROR);
  }

  /**
   * Creates an extended error code EDNS option.
   *
   * @param errorCode the extended error.
   * @param text optional error message intended for human readers.
   */
  public ExtendedErrorCodeOption(int errorCode, String text) {
    super(Code.EDNS_EXTENDED_ERROR);
    this.errorCode = errorCode;
    this.text = text;
  }

  /**
   * Creates an extended error code EDNS option.
   *
   * @param errorCode the extended error.
   */
  public ExtendedErrorCodeOption(int errorCode) {
    this(errorCode, null);
  }

  @Override
  void optionFromWire(DNSInput in) throws IOException {
    errorCode = in.readU16();
    if (in.remaining() > 0) {
      byte[] data = in.readByteArray();
      int len = data.length;

      // EDE text may be null terminated but MUST NOT be assumed to be
      if (data[data.length - 1] == 0) {
        len--;
      }

      text = new String(data, 0, len, StandardCharsets.UTF_8);
    }
  }

  @Override
  void optionToWire(DNSOutput out) {
    out.writeU16(errorCode);
    if (text != null && text.length() > 0) {
      out.writeByteArray(text.getBytes(StandardCharsets.UTF_8));
    }
  }

  @Override
  String optionToString() {
    if (text == null) {
      return codes.getText(errorCode);
    }
    return codes.getText(errorCode) + ": " + text;
  }
}

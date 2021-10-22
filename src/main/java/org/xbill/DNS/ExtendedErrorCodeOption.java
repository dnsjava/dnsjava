// SPDX-License-Identifier: BSD-3-Clause
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
    codes.add(OTHER, "OTHER");
    codes.add(UNSUPPORTED_DNSKEY_ALGORITHM, "UNSUPPORTED_DNSKEY_ALGORITHM");
    codes.add(UNSUPPORTED_DS_DIGEST_TYPE, "UNSUPPORTED_DS_DIGEST_TYPE");
    codes.add(STALE_ANSWER, "STALE_ANSWER");
    codes.add(FORGED_ANSWER, "FORGED_ANSWER");
    codes.add(DNSSEC_INDETERMINATE, "DNSSEC_INDETERMINATE");
    codes.add(DNSSEC_BOGUS, "DNSSEC_BOGUS");
    codes.add(SIGNATURE_EXPIRED, "SIGNATURE_EXPIRED");
    codes.add(SIGNATURE_NOT_YET_VALID, "SIGNATURE_NOT_YET_VALID");
    codes.add(DNSKEY_MISSING, "DNSKEY_MISSING");
    codes.add(RRSIGS_MISSING, "RRSIGS_MISSING");
    codes.add(NO_ZONE_KEY_BIT_SET, "NO_ZONE_KEY_BIT_SET");
    codes.add(NSEC_MISSING, "NSEC_MISSING");
    codes.add(CACHED_ERROR, "CACHED_ERROR");
    codes.add(NOT_READY, "NOT_READY");
    codes.add(BLOCKED, "BLOCKED");
    codes.add(CENSORED, "CENSORED");
    codes.add(FILTERED, "FILTERED");
    codes.add(PROHIBITED, "PROHIBITED");
    codes.add(STALE_NXDOMAIN_ANSWER, "STALE_NXDOMAIN_ANSWER");
    codes.add(NOT_AUTHORITATIVE, "NOT_AUTHORITATIVE");
    codes.add(NOT_SUPPORTED, "NOT_SUPPORTED");
    codes.add(NO_REACHABLE_AUTHORITY, "NO_REACHABLE_AUTHORITY");
    codes.add(NETWORK_ERROR, "NETWORK_ERROR");
    codes.add(INVALID_DATA, "INVALID_DATA");
  }

  /**
   * Gets the text mnemonic corresponding to an EDE value.
   *
   * @since 3.5
   */
  public static String text(int code) {
    return codes.getText(code);
  }

  /**
   * Gets the numeric value corresponding to an EDE text mnemonic.
   *
   * @since 3.5
   */
  public static int code(String text) {
    return codes.getValue(text);
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

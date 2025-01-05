// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants and functions relating to flags in the DNS header.
 *
 * @author Brian Wellington
 */
public final class Flags {

  private static final Mnemonic HEADER_FLAGS = new Mnemonic("DNS Header Flag", Mnemonic.CASE_LOWER);

  /** query/response */
  public static final byte QR = 0;

  /** authoritative answer */
  public static final byte AA = 5;

  /** truncated */
  public static final byte TC = 6;

  /** recursion desired */
  public static final byte RD = 7;

  /** recursion available */
  public static final byte RA = 8;

  /** authenticated data */
  public static final byte AD = 10;

  /** (security) checking disabled */
  public static final byte CD = 11;

  /** dnssec ok (extended) */
  public static final int DO = ExtendedFlags.DO;

  static {
    HEADER_FLAGS.setMaximum(0xF);
    HEADER_FLAGS.setPrefix("FLAG");
    HEADER_FLAGS.setNumericAllowed(true);

    HEADER_FLAGS.add(QR, "qr");
    HEADER_FLAGS.add(AA, "aa");
    HEADER_FLAGS.add(TC, "tc");
    HEADER_FLAGS.add(RD, "rd");
    HEADER_FLAGS.add(RA, "ra");
    HEADER_FLAGS.add(AD, "ad");
    HEADER_FLAGS.add(CD, "cd");
  }

  private Flags() {}

  /** Converts a numeric Flag into a String */
  public static String string(int i) {
    return HEADER_FLAGS.getText(i);
  }

  /** Converts a String representation of an Flag into its numeric value */
  public static int value(String s) {
    return HEADER_FLAGS.getValue(s);
  }

  /**
   * Indicates if a bit in the flags field is a flag or not. If it's part of the rcode or opcode,
   * it's not.
   */
  public static boolean isFlag(int index) {
    HEADER_FLAGS.check(index);
    return (index < 1 || index > 4) && (index < 12);
  }
}

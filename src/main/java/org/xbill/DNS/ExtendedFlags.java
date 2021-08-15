// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants and functions relating to EDNS flags.
 *
 * @author Brian Wellington
 */
public final class ExtendedFlags {

  private static final Mnemonic extflags = new Mnemonic("EDNS Flag", Mnemonic.CASE_LOWER);

  /** dnssec ok */
  public static final int DO = 0x8000;

  static {
    extflags.setMaximum(0xFFFF);
    extflags.setPrefix("FLAG");
    extflags.setNumericAllowed(true);

    extflags.add(DO, "do");
  }

  private ExtendedFlags() {}

  /** Converts a numeric extended flag into a String */
  public static String string(int i) {
    return extflags.getText(i);
  }

  /**
   * Converts a numeric extended flag into a String
   *
   * @param bit the flag as a bit value according to IANA allocation
   */
  public static String stringFromBit(int bit) {
    return extflags.getText((1 << (15 - bit)));
  }

  /** Converts a textual representation of an extended flag into its numeric value */
  public static int value(String s) {
    return extflags.getValue(s);
  }
}

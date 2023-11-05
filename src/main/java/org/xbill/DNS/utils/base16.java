// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.utils;

import java.io.ByteArrayOutputStream;

/**
 * Routines for converting between Strings of hex-encoded data and arrays of binary data. This is
 * not actually used by DNS.
 *
 * @author Brian Wellington
 */
public class base16 {

  private static final String BASE_16_CHARS = "0123456789ABCDEF";

  private base16() {}

  /**
   * Convert binary data to a hex-encoded String
   *
   * @param b An array containing binary data
   * @return A String containing the encoded data
   */
  public static String toString(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte item : b) {
      short value = (short) (item & 0xFF);
      byte high = (byte) (value >> 4);
      byte low = (byte) (value & 0xF);
      sb.append(BASE_16_CHARS.charAt(high));
      sb.append(BASE_16_CHARS.charAt(low));
    }
    return sb.toString();
  }

  /**
   * Convert binary data to a hex-encoded string, line-wrapped at {@code lineLength} characters.
   *
   * @param b An array containing binary data
   * @param lineLength The number of characters per line
   * @param prefix A string prefixing the characters on each line
   * @param addClose Whether to add a close parenthesis or not
   * @return A String containing the encoded data
   * @since 3.6
   */
  public static String toString(byte[] b, int lineLength, String prefix, boolean addClose) {
    return BaseUtils.wrapLines(toString(b), lineLength, prefix, addClose);
  }

  /**
   * Convert a hex-encoded String to binary data, ignoring {@link Character#isWhitespace(char)
   * whitespace} characters.
   *
   * <p>Returns {@code null}
   *
   * <ul>
   *   <li>when {@code str} is {@code null},
   *   <li>when non-hex digits or non-whitespace characters are encountered.
   *
   * @param str A String containing the encoded data.
   * @return An array containing the binary data, or null if the string is invalid.
   */
  public static byte[] fromString(String str) {
    if (str == null) {
      return null;
    }

    if (str.isEmpty()) {
      return new byte[0];
    }

    ByteArrayOutputStream bs = new ByteArrayOutputStream();
    for (int i = 0; i < str.length(); i++) {
      char c = str.charAt(i);
      if (c >= 48 && c <= 57 || c >= 65 && c <= 70) {
        // 0-9, A-Z
        bs.write(c);
      } else if (c >= 97 && c <= 102) {
        // convert a-z to A-Z
        bs.write(c - 32);
      } else if (!Character.isWhitespace(c)) {
        return null;
      }
    }

    byte[] in = bs.toByteArray();
    if ((in.length & 1) != 0) {
      return null;
    }

    bs.reset();

    for (int i = 0; i < in.length; i += 2) {
      byte high = (byte) BASE_16_CHARS.indexOf(in[i]);
      byte low = (byte) BASE_16_CHARS.indexOf(in[i + 1]);
      bs.write((high << 4) + (low & 0x0F));
    }
    return bs.toByteArray();
  }
}

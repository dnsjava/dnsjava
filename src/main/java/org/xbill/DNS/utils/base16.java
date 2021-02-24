// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.utils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Routines for converting between Strings of hex-encoded data and arrays of binary data. This is
 * not actually used by DNS.
 *
 * @author Brian Wellington
 */
public class base16 {

  private static final String Base16 = "0123456789ABCDEF";

  private base16() {}

  /**
   * Convert binary data to a hex-encoded String
   *
   * @param b An array containing binary data
   * @return A String containing the encoded data
   */
  public static String toString(byte[] b) {
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    for (byte item : b) {
      short value = (short) (item & 0xFF);
      byte high = (byte) (value >> 4);
      byte low = (byte) (value & 0xF);
      os.write(Base16.charAt(high));
      os.write(Base16.charAt(low));
    }
    return new String(os.toByteArray());
  }

  /**
   * Convert a hex-encoded String to binary data
   *
   * @param str A String containing the encoded data
   * @return An array containing the binary data, or null if the string is invalid
   */
  public static byte[] fromString(String str) {
    ByteArrayOutputStream bs = new ByteArrayOutputStream();
    byte[] raw = str.getBytes();
    for (byte b : raw) {
      if (!Character.isWhitespace((char) b)) {
        bs.write(b);
      }
    }
    byte[] in = bs.toByteArray();
    if (in.length % 2 != 0) {
      return null;
    }

    bs.reset();
    DataOutputStream ds = new DataOutputStream(bs);

    for (int i = 0; i < in.length; i += 2) {
      byte high = (byte) Base16.indexOf(Character.toUpperCase((char) in[i]));
      byte low = (byte) Base16.indexOf(Character.toUpperCase((char) in[i + 1]));
      try {
        ds.writeByte((high << 4) + low);
      } catch (IOException e) {
      }
    }
    return bs.toByteArray();
  }
}

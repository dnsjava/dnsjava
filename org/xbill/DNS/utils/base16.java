// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;
import java.util.*;

/**
 * Routines for converting between Strings of hex-encoded data and arrays of
 * binary data.  This is not actually used by DNS.
 *
 * @author Brian Wellington
 */

public class base16 {

static private final String Base16 = "0123456789ABCDEF";

private
base16() {}

/**
 * Convert binary data to a hex-encoded String
 * @param b An array containing binary data
 * @return A String containing the encoded data
 */
public static String
toString(byte [] b) {
	ByteArrayOutputStream os = new ByteArrayOutputStream();

	for (int i = 0; i < b.length; i++) {
		short value = (short) (b[i] & 0xFF);
		byte high = (byte) (value >> 4);
		byte low = (byte) (value & 0xF);
		os.write(Base16.charAt(high));
		os.write(Base16.charAt(low));
	}
	return new String(os.toByteArray());
}

/**
 * Convert a hex-encoded String to binary data
 * @param b A String containing the encoded data
 * @return An array containing the binary data, or null if the string is invalid
 */
public static byte []
fromString(String str) {
	if (str.length() % 2 != 0) {
		return null;
	}
	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	for (int i = 0; i < str.length(); i+=2) {
		byte high = (byte) Base16.indexOf(Character.toUpperCase(str.charAt(i)));
		byte low = (byte) Base16.indexOf(Character.toUpperCase(str.charAt(i+1)));
		try {
			ds.writeByte((high << 4) + low);
		}
		catch (IOException e) {
		}
	}
	return bs.toByteArray();
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS.utils;

import java.io.*;
import java.util.*;

public class base16 {

static private final String Base16 = "0123456789ABCDEF";

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

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;

/**
 * A routine to produce a nice looking hex dump
 *
 * @author Brian Wellington
 */

public class hexdump {

public static String
dump(String description, byte [] b, int offset, int length) {
	StringBuffer sb = new StringBuffer();

	sb.append(length);
	sb.append("b");
	if (description != null) {
		sb.append(" (");
		sb.append(description);
		sb.append(')');
	}
	sb.append(':');

	int prefixlen = sb.toString().length();
	prefixlen = (prefixlen + 8) & ~ 7;
	sb.append('\t');

	int perline = (80 - prefixlen) / 3;
	for (int i = 0; i < length; i++) {
		if (i != 0 && i % perline == 0) {
			sb.append('\n');
			for (int j = 0; j < prefixlen; j+=8)
				sb.append('\t');
		}
		int value = (int)(b[i + offset]) & 0xFF;
		if (value < 16)
			sb.append('0');
		sb.append(Integer.toHexString(value));
		sb.append(' ');
	}
	sb.append('\n');
	return sb.toString();
}

public static String
dump(String s, byte [] b) {
	return dump(s, b, 0, b.length);
}

}

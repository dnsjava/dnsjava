// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS flags
 *
 * @author Brian Wellington
 */

public final class Flags {

private static StringValueTable flags = new StringValueTable();

/** query/response */
public static final byte QR		= 0;

/** authoritative answer */
public static final byte AA		= 5;

/** truncated */
public static final byte TC		= 6;

/** recursion desired */
public static final byte RD		= 7;

/** recursion available */
public static final byte RA		= 8;

/** authenticated data */
public static final byte AD		= 10;

/** (security) checking disabled */
public static final byte CD		= 11;

static {
	flags.put2(QR, "qr");
	flags.put2(AA, "aa");
	flags.put2(TC, "tc");
	flags.put2(RD, "rd");
	flags.put2(RA, "ra");
	flags.put2(AD, "ad");
	flags.put2(CD, "cd");
}

private
Flags() {}

/** Converts a numeric Flag into a String */
public static String
string(int i) {
	if ((i >= 1 && i <= 4) || (i >= 12 && i <= 15))
		return null;
	String s = flags.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a String representation of an Flag into its numeric value */
public static byte
value(String s) {
	byte i = (byte) flags.getValue(s.toLowerCase());
	if (i >= 0)
		return i;
	try {
		return Byte.parseByte(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

}

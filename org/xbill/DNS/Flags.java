// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import DNS.utils.*;

public final class Flags {

private static StringValueTable flags = new StringValueTable();

public static final byte QR		= 0;
public static final byte AA		= 5;
public static final byte TC		= 6;
public static final byte RD		= 7;
public static final byte RA		= 8;
public static final byte AD		= 10;
public static final byte CD		= 11;

static {
	flags.put2(QR, "QR");
	flags.put2(AA, "AA");
	flags.put2(TC, "TC");
	flags.put2(RD, "RD");
	flags.put2(RA, "RA");
	flags.put2(AD, "AD");
	flags.put2(CD, "CD");
}

public static String
string(int i) {
	if ((i >= 1 && i <= 4) || (i >= 12 && i <= 15))
		return null;
	String s = flags.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

public static byte
value(String s) {
	byte i = (byte) flags.getValue(s.toUpperCase());
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

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
	flags.put2(QR, "qr");
	flags.put2(AA, "aa");
	flags.put2(TC, "tc");
	flags.put2(RD, "rd");
	flags.put2(RA, "ra");
	flags.put2(AD, "ad");
	flags.put2(CD, "cd");
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

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import DNS.utils.*;

public final class Rcode {

private static StringValueTable rcodes = new StringValueTable();

public static final byte NOERROR	= 0;
public static final byte FORMERR	= 1;
public static final byte SERVFAIL	= 2;
public static final byte NXDOMAIN	= 3;
public static final byte NOTIMPL	= 4;
public static final byte REFUSED	= 5;
public static final byte YXDOMAIN	= 6;
public static final byte YXRRSET	= 7;
public static final byte NXRRSET	= 8;
public static final byte NOTAUTH	= 9;
public static final byte NOTZONE	= 10;

/* TSIG only rcodes */
public static final byte BADSIG		= 16;
public static final byte BADKEY		= 17;
public static final byte BADTIME	= 18;
public static final byte BADID          = 19;

static {
	rcodes.put2(NOERROR, "NOERROR");
	rcodes.put2(FORMERR, "FORMERR");
	rcodes.put2(SERVFAIL, "SERVFAIL");
	rcodes.put2(NXDOMAIN, "NXDOMAIN");
	rcodes.put2(NOTIMPL, "NOTIMPL");
	rcodes.put2(REFUSED, "REFUSED");
	rcodes.put2(YXDOMAIN, "YXDOMAIN");
	rcodes.put2(YXRRSET, "YXRRSET");
	rcodes.put2(NXRRSET, "NXRRSET");
	rcodes.put2(NOTAUTH, "NOTAUTH");
	rcodes.put2(NOTZONE, "NOTZONE");
	rcodes.put2(BADSIG, "BADSIG");
	rcodes.put2(BADKEY, "BADKEY");
	rcodes.put2(BADTIME, "BADTIME");
	rcodes.put2(BADID, "BADID");
}

public static String
string(int i) {
	String s = rcodes.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

public static byte
value(String s) {
	byte i = (byte) rcodes.getValue(s.toUpperCase());
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

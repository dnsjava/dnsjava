// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS rcodes (error values)
 *
 * @author Brian Wellington
 */

public final class Rcode {

private static StringValueTable rcodes = new StringValueTable();

/** No error */
public static final byte NOERROR	= 0;

/** Format error */
public static final byte FORMERR	= 1;

/** Server failure */
public static final byte SERVFAIL	= 2;

/** The name does not exist */
public static final byte NXDOMAIN	= 3;

/** The operation requested is not implemented */
public static final byte NOTIMPL	= 4;

/** The operation was refused by the server */
public static final byte REFUSED	= 5;

/** The name exists */
public static final byte YXDOMAIN	= 6;

/** The RRset (name, type) exists */
public static final byte YXRRSET	= 7;

/** The RRset (name, type) does not exist */
public static final byte NXRRSET	= 8;

/** The requestor is not authorized to perform this operation */
public static final byte NOTAUTH	= 9;

/** The zone specified is not a zone */
public static final byte NOTZONE	= 10;

/* TSIG only rcodes */
/** The signature is invalid (TSIG extended error) */
public static final byte BADSIG		= 16;

/** The key is invalid (TSIG extended error) */
public static final byte BADKEY		= 17;

/** The time is out of range (TSIG extended error) */
public static final byte BADTIME	= 18;

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
}

private
Rcode() {}

/** Converts a numeric Rcode into a String */
public static String
string(int i) {
	String s = rcodes.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a String representation of an Rcode into its numeric value */
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

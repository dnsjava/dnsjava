// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS opcodes
 *
 * @author Brian Wellington
 */

public final class Opcode {

private static StringValueTable opcodes = new StringValueTable();

/** A standard query */
public static final byte QUERY		= 0;

/** An inverse query (deprecated) */
public static final byte IQUERY		= 1;

/** A server status request (not used) */
public static final byte STATUS		= 2;

/**
 * A message from a primary to a secondary server to initiate a zone transfer
 */
public static final byte NOTIFY		= 4;

/** A dynamic update message */
public static final byte UPDATE		= 5;

static {
	opcodes.put2(QUERY, "QUERY");
	opcodes.put2(IQUERY, "IQUERY");
	opcodes.put2(STATUS, "STATUS");
	opcodes.put2(NOTIFY, "NOTIFY");
	opcodes.put2(UPDATE, "UPDATE");
}

private
Opcode() {}

/** Converts a numeric Opcode into a String */
public static String
string(int i) {
	String s = opcodes.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a String representation of an Opcode into its numeric value */
public static byte
value(String s) {
	byte i = (byte) opcodes.getValue(s.toUpperCase());
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

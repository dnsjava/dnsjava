// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import DNS.utils.*;

public final class Opcode {

private static StringValueTable opcodes = new StringValueTable();

public static final byte QUERY		= 0;
public static final byte NOTIFY		= 4;
public static final byte UPDATE		= 5;

static {
	opcodes.put2(QUERY, "QUERY");
	opcodes.put2(NOTIFY, "NOTIFY");
	opcodes.put2(UPDATE, "UPDATE");
}

public static String
string(int i) {
	String s = opcodes.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

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

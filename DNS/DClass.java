// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import DNS.utils.*;

public final class DClass {

private static StringValueTable classes = new StringValueTable();

public static final short IN		= 1;
public static final short CHAOS		= 3;
public static final short HESIOD	= 4;
public static final short NONE		= 254;
public static final short ANY		= 255;

static {
	classes.put2(IN, "IN");
	classes.put2(CHAOS, "CHAOS");
	classes.put2(HESIOD, "HESIOD");
	classes.put2(NONE, "NONE");
	classes.put2(ANY, "ANY");
}

public static String
string(int i) {
	String s = classes.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

public static short
value(String s) {
	short i = (short) classes.getValue(s.toUpperCase());
	if (i >= 0)
		return i;
	try {
		return Short.parseShort(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

}

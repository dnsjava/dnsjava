// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS classes.  This is called DClass
 * since Class was already taken.
 *
 * @author Brian Wellington
 */

public final class DClass {

private static StringValueTable classes = new StringValueTable();

/** Internet */
public static final short IN		= 1;

/** Chaos network (MIT) */
public static final short CHAOS		= 3;

/** Hesiod name server (MIT) */
public static final short HESIOD	= 4;

/** Special value used in dynamic update messages */
public static final short NONE		= 254;

/** Matches any class */
public static final short ANY		= 255;

static {
	classes.put2(IN, "IN");
	classes.put2(CHAOS, "CHAOS");
	classes.put2(HESIOD, "HESIOD");
	classes.put2(NONE, "NONE");
	classes.put2(ANY, "ANY");
}

private
DClass() {}

/** Converts a numeric Class into a String */
public static String
string(int i) {
	String s = classes.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a String representation of an Class into its numeric value */
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

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS classes.  This is called DClass
 * to avoid confusion with Class.
 *
 * @author Brian Wellington
 */

public final class DClass {

private static StringValueTable classes = new StringValueTable();

/** Internet */
public static final short IN		= 1;

/** Chaos network (MIT) */
public static final short CH		= 3;

/** Chaos network (MIT, alternate name) */
public static final short CHAOS		= 3;

/** Hesiod name server (MIT) */
public static final short HESIOD	= 4;

/** Special value used in dynamic update messages */
public static final short NONE		= 254;

/** Matches any class */
public static final short ANY		= 255;

private static Short [] classcache = new Short [5];

static {
	for (short i = 0; i < classcache.length; i++)
		classcache[i] = new Short(i);
	classes.put2(IN, "IN");
	classes.put2(CHAOS, "CHAOS");
	classes.put2(CH, "CH");
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
	return (s != null) ? s : ("CLASS" + i);
}

/**
 * Converts a String representation of a DClass into its numeric value
 * @return The class code, or -1 on error.
 */
public static int
value(String s) {
	s = s.toUpperCase();
	int i = classes.getValue(s);
	if (i >= 0)
		return i;
	if (s.startsWith("CLASS")) {
		try {
			int dclass = Integer.parseInt(s.substring(5));
			if (dclass < 0 || dclass > 0xFFFF)
				return -1;
			return dclass;
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
	return -1;
}

/* Converts a class into a Short, for use in Hashmaps, etc. */
static Short
toShort(short dclass) {
	if (dclass < classcache.length)
		return (classcache[dclass]);
	return new Short(dclass);
}

}

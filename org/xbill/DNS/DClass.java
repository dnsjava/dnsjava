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

/** Internet */
public static final short IN		= 1;

/** Chaos network (MIT) */
public static final short CH		= 3;

/** Chaos network (MIT, alternate name) */
public static final short CHAOS		= 3;

/** Hesiod name server (MIT) */
public static final short HS		= 4;

/** Hesiod name server (MIT, alternate name) */
public static final short HESIOD	= 4;

/** Special value used in dynamic update messages */
public static final short NONE		= 254;

/** Matches any class */
public static final short ANY		= 255;

private static Integer [] classcache = new Integer[5];

static {
	for (int i = 0; i < classcache.length; i++)
		classcache[i] = new Integer(i);
}

private
DClass() {}

/**
 * Converts a numeric DClass into a String
 * @return The canonical string representation of the class
 * @throws IllegalArgumentException The class is out of range.
 */
public static String
string(int i) {
	if (i < 0 || i > 0xFFFF)
		throw new IllegalArgumentException("class out of range: " + i);
	switch (i) {
	case IN: return "IN";
	case CH: return "CH";
	case HS: return "HS";
	case NONE: return "NONE";
	case ANY: return "ANY";
	default: return "CLASS" + i;
	}
}

/**
 * Converts a String representation of a DClass into its numeric value
 * @return The class code, or -1 on error.
 */
public static int
value(String s) {
	s = s.toUpperCase();
	if (s.equals("IN"))
		return IN;
	else if (s.equals("CH") || s.equals("CHAOS"))
		return CH;
	else if (s.equals("HS") || s.equals("HESIOS"))
		return HS;
	else if (s.equals("NONE"))
		return NONE;
	else if (s.equals("ANY"))
		return ANY;
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

/* Converts a class into an Integer, for use in Hashmaps, etc. */
static Integer
toInteger(int dclass) {
	if (dclass >= 0 && dclass < classcache.length)
		return (classcache[dclass]);
	return new Integer(dclass);
}

}

// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.utils;

import java.util.HashMap;

/**
 * A table used for storing mappings between Strings and constant values
 * and lookups in either direction.
 *
 * @author Brian Wellington
 */

public class StringValueTable {

private HashMap s2v, v2s;

public
StringValueTable() {
	s2v = new HashMap();
	v2s = new HashMap();
}

/**
 * Adds a new String/value pair
 * @param v The value
 * @param s The string
 */
public void
put2(int v, String s) {
	Integer V = new Integer(v);
	s2v.put(s, V);
	v2s.put(V, s);
}

/**
 * Finds the String associated with the given value
 * @param v The value
 * @return The corresponding String, or null if there is none
 */
public String
getString(int v) {
	return (String) v2s.get(new Integer(v));
}

/**
 * Finds the value associated with the given String
 * @param s The String
 * @return The corresponding value, or -1 if there is none
 */
public int
getValue(String s) {
	Integer V = (Integer) s2v.get(s);
	return (V == null) ? (-1) : V.intValue();
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS.utils;

import java.util.Hashtable;

public class StringValueTable {

Hashtable s2v, v2s;

public
StringValueTable() {
	s2v = new Hashtable();
	v2s = new Hashtable();
}

public void
put2(int v, String s) {
	Integer V = new Integer(v);
	s2v.put(s, V);
	v2s.put(V, s);
}

public String
getString(int v) {
	return (String) v2s.get(new Integer(v));
}

public int
getValue(String s) {
	Integer V = (Integer) s2v.get(s);
	return (V == null) ? (-1) : V.intValue();
}

}

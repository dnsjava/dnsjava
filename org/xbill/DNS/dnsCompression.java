// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.Hashtable;

public class dnsCompression {

Hashtable h;

public
dnsCompression() {
	h = new Hashtable();
}

public void
add(int pos, dnsName name) {
	h.put (new Integer(pos), name);
	h.put (name, new Integer(pos));
}

public dnsName
get(int pos) {
	return (dnsName)h.get(new Integer(pos));
}

public int
get(dnsName name) {
	Integer I = (Integer) h.get(name);
	return (I == null) ? (-1) : I.intValue();
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.Hashtable;

class Compression {

private Hashtable h;

public
Compression() {
	h = new Hashtable();
}

public void
add(int pos, Name name) {
	h.put (new Integer(pos), name);
	h.put (name, new Integer(pos));
}

public Name
get(int pos) {
	return (Name)h.get(new Integer(pos));
}

public int
get(Name name) {
	Integer I = (Integer) h.get(name);
	return (I == null) ? (-1) : I.intValue();
}

}

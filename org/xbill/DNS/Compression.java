// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.Hashtable;

/**
 * DNS Compression object.  Name compression and decompression are supported.
 * @see Name
 *
 * @author Brian Wellington
 */

class Compression {

private Hashtable h;

/**
 * Creates a new Compression object, suitable for either compression or
 * decompression.
 */
public
Compression() {
	h = new Hashtable();
}

/** Adds a compression entry mapping a name to a position.  */
public void
add(int pos, Name name) {
	h.put (new Integer(pos), name);
	h.put (name, new Integer(pos));
}

/** Retrieves the name at the specified position.  Used for decompression */
public Name
get(int pos) {
	return (Name)h.get(new Integer(pos));
}

/**
 * Retrieves the position of the given name, if it has been previously
 * included in the message.  Used for compression
 */
public int
get(Name name) {
	Integer I = (Integer) h.get(name);
	return (I == null) ? (-1) : I.intValue();
}

}

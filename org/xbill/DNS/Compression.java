// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;

/**
 * DNS Name Compression object.
 * @see Name
 *
 * @author Brian Wellington
 */

class Compression {

private Map h;

/**
 * Creates a new Compression object.
 */
public
Compression() {
	h = new HashMap();
}

/** Adds a compression entry mapping a name to a position.  */
public void
add(int pos, Name name) {
	h.put (name, new Integer(pos));
}

/**
 * Retrieves the position of the given name, if it has been previously
 * included in the message.
 */
public int
get(Name name) {
	Integer I = (Integer) h.get(name);
	return (I == null) ? (-1) : I.intValue();
}

}

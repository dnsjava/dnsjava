// Copyright (c) 2001 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

/**
 * A TypeMap is basically a hash table indexed by type.
 *
 * @author Brian Wellington
 */

class TypeMap {

private Hashtable data;

TypeMap() {
	data = new Hashtable();
}

/**
 * Finds the object corresponding to the given type.
 */
Object
get(short type) {
	if (type == Type.ANY)
		throw new RuntimeException("called TypeMap.get() with ANY");
	return data.get(new Short(type));
}

/**
 * Finds the objects corresponding to the given type, which may be ANY.
 */
Object []
getMultiple(short type) {
	Object [] out;
	int n;

	if (type != Type.ANY) {
		Object o = get(type);
		if (o == null)
			return null;
		out = new Object[1];
		out[0] = o;
		return out;
	}
	else {
		synchronized (data) {
			int size = data.size();
			out = new Object[size];
			Enumeration e = data.elements();
			n = 0;
			while (e.hasMoreElements())
				out[n++] = e.nextElement();
		}
	}
	return out;
}

/**
 * Associates an object with a type.
 */
void
put(short type, Object value) {
	synchronized (data) {
		data.put(new Short(type), value);
	}
}

/**
 * Removes the object with the given type.
 */
void
remove(short type) {
	data.remove(new Short(type));
}

/**
 * Is this map empty?
 */
boolean
isEmpty() {
	return data.isEmpty();
}

}

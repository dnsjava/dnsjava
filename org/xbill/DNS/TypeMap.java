// Copyright (c) 2001 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

/**
 * A TypeMap is basically a hash table indexed by type.
 *
 * @author Brian Wellington
 */

class TypeMap {

private Map data;

TypeMap() {
	data = new HashMap(3);
}

/**
 * Finds the object corresponding to the given type.
 */
Object
get(short type) {
	if (type == Type.ANY)
		throw new RuntimeException("called TypeMap.get() with ANY");
	return data.get(Type.toShort(type));
}

/**
 * Returns an array of all objects in the TypeMap.
 */
Object []
getAll() {
	Object [] out;
	int n;

	synchronized (data) {
		int size = data.size();
		out = new Object[size];
		Iterator it = data.values().iterator();
		n = 0;
		while (it.hasNext())
			out[n++] = it.next();
	}
	return out;
}

/**
 * Associates an object with a type.
 */
void
put(short type, Object value) {
	synchronized (data) {
		data.put(Type.toShort(type), value);
	}
}

/**
 * Removes the object with the given type.
 */
void
remove(short type) {
	data.remove(Type.toShort(type));
}

/**
 * Is this map empty?
 */
boolean
isEmpty() {
	return data.isEmpty();
}

}

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
	Object [] out = getMultiple(type);
	if (out == null || out.length == 0)
		return null;
	if (out.length == 1)
		return out[0];
	else
		throw new RuntimeException("TypeMap error: " + out.length);
}

private int
fill(Object [] array, int start, Enumeration e) {
	while (e.hasMoreElements()) 
		array[start++] = e.nextElement();
	return start;
}

/**
 * Finds the objects corresponding to the given type, which may be ANY.
 */
Object []
getMultiple(short type) {
	Object [] out;
	Vector v;
	int n;

	if (type != Type.ANY) {
		v = (Vector) data.get(new Short(type));
		if (v == null)
			return null;
		synchronized (v) {
			out = new Object[v.size()];
			n = fill(out, 0, v.elements());
		}
	}
	else {
		synchronized (data) {
			int size = data.size();
			while (true) {
				try {
					out = new Object[size];
					Enumeration e = data.elements();
					n = 0;
					while (e.hasMoreElements()) {
						v = (Vector) e.nextElement();
						n = fill(out, n, v.elements());
					}
					break;
				}
				catch (ArrayIndexOutOfBoundsException e) {
					size *= 2;
				}
			}
		}
	}
	if (n != out.length) {
		Object [] out2 = out;
		out = new Object[n];
		System.arraycopy(out2, 0, out, 0, n);
	}
	return out;
}

/**
 * Associates an object with a type.
 */
void
put(short type, Object value) {
	Short T = new Short(type);
	Vector v = (Vector) data.get(T);
	if (v == null) {
		synchronized (data) {
			data.put(T, v = new Vector());
		}
	}
	synchronized (v) {
		v.removeElement(value);
		v.addElement(value);
	}
}

/**
 * Removes the object with the given type.
 */
void
remove(short type) {
	Short T = new Short(type);
	Vector v = (Vector) data.get(T);
	if (v == null)
		return;
	synchronized (data) {
		data.remove(T);
	}
}

/**
 * Is this map empty?
 */
boolean
isEmpty() {
	return data.isEmpty();
}

}

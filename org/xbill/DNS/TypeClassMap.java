// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;

/**
 * A TypeClassMap is indexed on two short integer variables: type and class.
 * Either value may be specified as ANY, which means that only the other
 * value is used.  This must not require a linear search if neither
 * index is ANY, should not require a linear search if class is ANY,
 * and may require a linear search if type is ANY.
 *
 * @author Brian Wellington
 */

class TypeClassMap {

class Wrapper {
	short dclass;
	Object object;

	Wrapper(short _dclass, Object _object) {
		dclass = _dclass;
		object = _object;
	}

	public boolean
	equals(Object o) {
		if (!(o instanceof Wrapper))
			return false;
		Wrapper w = (Wrapper) o;
		return (dclass == w.dclass);
	}
}

private Hashtable data;

TypeClassMap() {
	data = new Hashtable();
}

/**
 * Finds the object corresponding to the given type and class.
 */
Object
get(short type, short dclass) {
	Object [] out = getMultiple(type, dclass);
	if (out == null || out.length == 0)
		return null;
	if (out.length == 1)
		return out[0];
	else
		throw new RuntimeException("TypeClassMap error: " + out.length);
}

private int
fill(Object [] array, int start, Enumeration e, short dclass) {
	while (e.hasMoreElements()) {
		Wrapper w = (Wrapper) e.nextElement();
		if (dclass == DClass.ANY || w.dclass == dclass)
			array[start++] = w.object;
	}
	return start;
}

/**
 * Finds the objects corresponding to the given type and class, which may
 * be ANY.
 */
Object []
getMultiple(short type, short dclass) {
	Object [] out;
	Vector v;
	int n;

	if (type != Type.ANY) {
		v = (Vector) data.get(new Short(type));
		if (v == null)
			return null;
		synchronized (v) {
			out = new Object[v.size()];
			n = fill(out, 0, v.elements(), dclass);
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
						n = fill(out, n, v.elements(),
							 dclass);
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
 * Associates an object with a type and class.
 */
void
put(short type, short dclass, Object value) {
	Short T = new Short(type);
	Vector v = (Vector) data.get(T);
	if (v == null) {
		synchronized (data) {
			data.put(T, v = new Vector());
		}
	}
	Wrapper w = new Wrapper(dclass, value);
	synchronized (v) {
		v.removeElement(w);
		v.addElement(w);
	}
}

/**
 * Removes the object with the given type and class.
 */
void
remove(short type, short dclass) {
	Short T = new Short(type);
	Vector v = (Vector) data.get(T);
	if (v == null)
		return;
	Wrapper w = new Wrapper(dclass, null);
	synchronized (v) {
		v.removeElement(w);
		if (v.size() == 0)
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

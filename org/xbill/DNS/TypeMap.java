// Copyright (c) 2001 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

/**
 * A TypeMap is a type-indexed hash table.
 *
 * @author Brian Wellington
 */

class TypeMap {

/* The Map stores data if there is more than one type. */
private Map data;

/* Otherwise the data is stored explicitly. */
private TypedObject object;

TypeMap() {
}

/**
 * Finds the object corresponding to the given type.
 */
synchronized Object
get(short type) {
	if (type == Type.ANY)
		throw new RuntimeException("called TypeMap.get() with ANY");
	if (data != null)
		return data.get(Type.toShort(type));
	else if (object != null && object.getType() == type)
		return object;
	else
		return null;
}

/**
 * Returns an array of all objects in the TypeMap.
 */
synchronized Object []
getAll() {
	Object [] out;
	int n;

	if (data != null)
		return (Object []) data.values().toArray();
	else if (object != null)
		return new Object[] {object};
	else
		return new Object[0];
}

/**
 * Associates an object with a type.
 */
synchronized void
put(short type, TypedObject value) {
	if (object != null) {
		if (type == object.getType())
			object = value;
		else {
			data = new HashMap(2);
			data.put(Type.toShort(object.getType()), object);
			object = null;
		}
	}
	if (data != null)
		data.put(Type.toShort(type), value);
	else
		object = value;
}

/**
 * Removes the object with the given type.
 */
synchronized void
remove(short type) {
	if (data != null)
		data.remove(Type.toShort(type));
	else if (object != null && object.getType() == type)
		object = null;
}

/**
 * Is this map empty?
 */
synchronized boolean
isEmpty() {
	return ((data == null && object == null) || data.isEmpty());
}

}

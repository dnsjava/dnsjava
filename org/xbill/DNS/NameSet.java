// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The shared superclass of Zone and Cache.  All names are stored in a
 * hashtable.  Each name contains a hashtable indexed on type and class. 
 *
 * @author Brian Wellington
 */

class NameSet {

private Hashtable data;

/** Creates an empty NameSet */
protected
NameSet() {
	data = new Hashtable();
}

/** Deletes all sets in a NameSet */
protected void
clear() {
	data = new Hashtable();
}

/**
 * Finds all matching sets.  This traverses CNAMEs, and has provisions for 
 * type/class ANY.
 */
protected Object []
findSets(Name name, short type) {
	Object [] array;
	Object o;

	TypeMap nameInfo = findName(name);
	if (nameInfo == null) 
		return null;
	while (true) {
		if (type == Type.ANY) {
			array = nameInfo.getMultiple(type);
			if (array != null)
				return array;
		}
		else {
			o = nameInfo.get(type);
			if (o != null)
				return new Object[] {o};
		}
		if (type == Type.CNAME)
			break;
		else
			type = Type.CNAME;
	}
	return null;
}

/**
 * Finds all sets that exactly match.  This does not traverse CNAMEs or handle
 * Type ANY queries.
 */
protected Object
findExactSet(Name name, short type) {
	TypeMap nameInfo = findName(name);
	if (nameInfo == null)
		return null;
	return nameInfo.get(type);
}

/**
 * Finds all records for a given name, if the name exists.
 */
protected TypeMap
findName(Name name) {
	return (TypeMap) data.get(name);
}

/**
 * Adds a set associated with a name/type.  The data contained in the
 * set is abstract.
 */
protected void
addSet(Name name, short type, Object set) {
	TypeMap nameInfo = findName(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new TypeMap());
	synchronized (nameInfo) {
		nameInfo.put(type, set);
	}
}

/**
 * Removes the given set from the name/type/class.  The data contained in the
 * set is abstract.
 */
protected void
removeSet(Name name, short type, Object set) {
	TypeMap nameInfo = findName(name);
	if (nameInfo == null)
		return;
	Object o = nameInfo.get(type);
	if (o != set && type != Type.CNAME) {
		type = Type.CNAME;
		o = nameInfo.get(type);
	}
	if (o == set) {
		synchronized (nameInfo) {
			nameInfo.remove(type);
		}
		if (nameInfo.isEmpty())
			data.remove(name);
	}
}

/**
 * Removes all data associated with the given name.
 */
protected void
removeName(Name name) {
	data.remove(name);
}

/**
 * Returns a list of all names stored in this NameSet.
 */
Enumeration
names() {
	return data.keys();
}

/** Converts the NameSet to a String */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	Enumeration e = data.elements();
	while (e.hasMoreElements()) {
		TypeMap nameInfo = (TypeMap) e.nextElement();
		Object [] elements = nameInfo.getMultiple(Type.ANY);
		if (elements == null)
			continue;
		for (int i = 0; i < elements.length; i++)
			sb.append(elements[i]);
	}
	return sb.toString();
}
	
}

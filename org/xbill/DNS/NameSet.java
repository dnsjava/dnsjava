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
findSets(Name name, short type, short dclass) {
	Object [] array;
	Object o;

	TypeClassMap nameInfo = findName(name);
	if (nameInfo == null) 
		return null;
	while (true) {
		if (type == Type.ANY || dclass == DClass.ANY) {
			array = nameInfo.getMultiple(type, dclass);
			if (array != null)
				return array;
		}
		else {
			o = nameInfo.get(type, dclass);
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
findExactSet(Name name, short type, short dclass) {
	TypeClassMap nameInfo = findName(name);
	if (nameInfo == null)
		return null;
	return nameInfo.get(type, dclass);
}

/**
 * Finds all records for a given name, if the name exists.
 */
protected TypeClassMap
findName(Name name) {
	return (TypeClassMap) data.get(name);
}

/**
 * Adds a set associated with a name/type/class.  The data contained in the
 * set is abstract.
 */
protected void
addSet(Name name, short type, short dclass, Object set) {
	TypeClassMap nameInfo = findName(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new TypeClassMap());
	synchronized (nameInfo) {
		nameInfo.put(type, dclass, set);
	}
}

/**
 * Removes the given set from the name/type/class.  The data contained in the
 * set is abstract.
 */
protected void
removeSet(Name name, short type, short dclass, Object set) {
	TypeClassMap nameInfo = findName(name);
	if (nameInfo == null)
		return;
	Object o = nameInfo.get(type, dclass);
	if (o != set && type != Type.CNAME) {
		type = Type.CNAME;
		o = nameInfo.get(type, dclass);
	}
	if (o == set) {
		synchronized (nameInfo) {
			nameInfo.remove(type, dclass);
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
		TypeClassMap nameInfo = (TypeClassMap) e.nextElement();
		Object [] elements = nameInfo.getMultiple(Type.ANY, DClass.ANY);
		if (elements == null)
			continue;
		for (int i = 0; i < elements.length; i++)
			sb.append(elements[i]);
	}
	return sb.toString();
}
	
}

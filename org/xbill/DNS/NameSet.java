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

/**
 * Finds all matching sets.  This traverses CNAMEs, and has provisions for 
 * Type ANY.
 */
protected Object []
findSets(Name name, short type, short dclass) {
	Object [] array;
	Object o;

	Hashtable nameInfo = findName(name);
	if (nameInfo == null) 
		return null;
	if (type == Type.ANY) {
		synchronized (nameInfo) {
			array = new Object[nameInfo.size()];
			int i = 0;
			Enumeration e = nameInfo.elements();
			while (e.hasMoreElements())
				array[i++] = e.nextElement();
		}
		return array;
	}
	o = nameInfo.get(new TypeClass(type, dclass));
	if (o != null) {
		array = new Object[1];
		array[0] = o;
		return array;
	}
	if (type != Type.CNAME) {
		o = nameInfo.get(new TypeClass(Type.CNAME, dclass));
		if (o == null)
			return null;
		else {
			array = new Object[1];
			array[0] = o;
			return array;
		}
	}
	return null;
}

/**
 * Finds all sets that exactly match.  This does not traverse CNAMEs or handle
 * Type ANY queries.
 */
protected Object
findExactSet(Name name, short type, short dclass) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		return null;
	return nameInfo.get(new TypeClass(type, dclass));
}

/**
 * Finds all records for a given name, if the name exists.
 */
protected Hashtable
findName(Name name) {
	return (Hashtable) data.get(name);
}

/**
 * Adds a set associated with a name/type/class.  The data contained in the
 * set is abstract.
 */
protected void
addSet(Name name, short type, short dclass, Object set) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new Hashtable());
	synchronized (nameInfo) {
		nameInfo.put(new TypeClass(type, dclass), set);
	}
}

/**
 * Removes the given set from the name/type/class.  The data contained in the
 * set is abstract.
 */
protected void
removeSet(Name name, short type, short dclass, Object set) {
	Hashtable nameInfo = findName(name);
	if (nameInfo == null)
		return;
	Object o = nameInfo.get(new TypeClass(type, dclass));
	if (o != set && type != Type.CNAME) {
		type = Type.CNAME;
		o = nameInfo.get(new TypeClass(type, dclass));
	}
	if (o == set) {
		synchronized (nameInfo) {
			nameInfo.remove(new TypeClass(type, dclass));
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

/** Converts the NameSet to a String */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	Enumeration e = data.elements();
	while (e.hasMoreElements()) {
		Hashtable nameInfo = (Hashtable) e.nextElement();
		Enumeration e2 = nameInfo.elements();
		while (e2.hasMoreElements())
			sb.append(e2.nextElement());
	}
	return sb.toString();
}
	
}

// Copyright (c) 1999-2001 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The shared superclass of Zone and Cache.  All names are stored in a
 * map.  Each name contains a map indexed by type.
 *
 * @author Brian Wellington
 */

class NameSet {

private Map data;
private Name origin;
private boolean isCache;

protected static Object NXRRSET = new Object();

/** Creates an empty NameSet for use as a Zone or Cache.  The origin is set
 * to the root.
 */
protected
NameSet(boolean isCache, Map map) {
	data = map;
	origin = Name.root;
	this.isCache = isCache;
}

protected
NameSet(boolean isCache) {
	this(isCache, new HashMap());
}

/** Sets the origin of the NameSet */
protected void
setOrigin(Name origin) {
	this.origin = origin;
}

/** Deletes all sets in a NameSet */
protected synchronized void
clear() {
	data.clear();
}

private final Object
lookupType(Object typelist, short type) {
	if (type == Type.ANY)
		throw new IllegalArgumentException
				("type ANY passed to NameSet.lookupType()");
	synchronized (typelist) {
		if (typelist instanceof LinkedList) {
			LinkedList list = (LinkedList) typelist;
			for (int i = 0; i < list.size(); i++) {
				TypedObject obj = (TypedObject) list.get(i);
				if (obj.getType() == type)
					return (obj);
			}
			return (null);
		} else {
			TypedObject obj = (TypedObject) typelist;
			if (obj.getType() == type)
				return (obj);
			return (null);
		}
	}
}

private final Object []
lookupAll(Object typelist) {
	synchronized (typelist) {
		if (typelist instanceof LinkedList)
			return ((LinkedList) typelist).toArray();
		else
			return (new Object[] {typelist});
	}
}

/**
 * Finds all matching sets or something that causes the lookup to stop.
 */
protected Object
lookup(Name name, short type) {
	Object bestns = null;
	Object o;
	int labels;
	int olabels;
	int tlabels;

	if (!name.subdomain(origin))
		return null;
	labels = name.labels();
	olabels = origin.labels();

	for (tlabels = olabels; tlabels <= labels; tlabels++) {
		boolean isorigin = (tlabels == olabels);
		boolean isexact = (tlabels == labels);
		Name tname;
		Object typelist;

		if (isorigin)
			tname = origin;
		else if (isexact)
			tname = name;
		else
			tname = new Name(name, labels - tlabels);

		synchronized (this) {
			typelist = data.get(tname);
		}
		if (typelist == null)
			continue;

		/* If this is an ANY lookup, return everything. */
		if (isexact && type == Type.ANY)
			return lookupAll(typelist);

		/* Look for an NS */
		if (!isorigin || isCache) {
			o = lookupType(typelist, Type.NS);
			if (o != null) {
				if (isCache)
					bestns = o;
				else
					return o;
			}
		}

		/*
		 * If this is the name, look for the actual type or a CNAME.
		 * Otherwise, look for a DNAME.
		 */
		if (isexact) {
			o = lookupType(typelist, type);
			if (o == null)
				o = lookupType(typelist, Type.CNAME);
			if (o != null)
				return o;
		} else {
			o = lookupType(typelist, Type.DNAME);
			if (o != null)
				return o;
		}

		/*
		 * If this is the name and this is a cache, look for an
		 * NXDOMAIN entry.
		 */
		if (isexact && isCache) {
			o = lookupType(typelist, (short)0);
			if (o != null)
				return o;
		}

		/*
		 * If this is the name and we haven't matched anything,
		 * return the special NXRRSET object.
		 */
		if (isexact)
			return NXRRSET;
	}
	return bestns;
}

/**
 * Finds all sets that exactly match.  This does not traverse CNAMEs or handle
 * Type ANY queries.
 */
protected Object
findExactSet(Name name, short type) {
	Object typelist;
	synchronized (this) {
		typelist = data.get(name);
	}
	if (typelist == null)
		return (null);
	return lookupType(typelist, type);
}

/**
 * Finds all sets at a name.
 */
protected Object []
findExactSets(Name name) {
	Object typelist;
	synchronized (this) {
		typelist = data.get(name);
	}
	if (typelist == null)
		return (new Object[0]);
	return lookupAll(typelist);
}

/**
 * Finds all records for a given name, if the name exists.
 */
private Object
findName(Name name) {
	return data.get(name);
}

/**
 * Adds a set associated with a name/type.  The data contained in the
 * set is abstract.
 */
protected void
addSet(Name name, short type, TypedObject set) {
	Object typelist;
	synchronized (this) {
		typelist = data.get(name);

		if (typelist == null) {
			/* No types are present. */
			data.put(name, set);
			return;
		} else if (!(typelist instanceof LinkedList)) {
			/* One type is present */
			TypedObject obj = (TypedObject) typelist;
			if (obj.getType() == type) {
				/* We're replacing it */
				data.put(name, set);
			} else {
				LinkedList list = new LinkedList();
				list.add(typelist);
				list.add(set);
				data.put(name, list);
			}
			return;
		}
	}
	/* More than one type is present */
	synchronized (typelist) {
		LinkedList list = (LinkedList) typelist;
		for (int i = 0; i < list.size(); i++) {
			TypedObject obj = (TypedObject) list.get(i);
			if (obj.getType() == type) {
				list.set(i, set);
				return;
			}
		}
		list.add(set);
	}
}

/**
 * Removes the given set with the name and type.  The data contained in the
 * set is abstract.
 */
protected void
removeSet(Name name, short type, TypedObject set) {
	Object typelist;
	synchronized (this) {
		typelist = data.get(name);
		if (typelist == null)
			return;
		else if (!(typelist instanceof LinkedList)) {
			if (typelist == set)
				data.remove(name);
			return;
		}
	}
	synchronized (typelist) {
		LinkedList list = (LinkedList) typelist;
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i) == set) {
				list.remove(i);
				return;
			}
		}
	}
}

/**
 * Removes all data associated with the given name.
 */
protected void
removeName(Name name) {
	synchronized (this) {
		data.remove(name);
	}
}

/**
 * Returns a list of all names stored in this NameSet.
 */
Iterator
names() {
	return data.keySet().iterator();
}

/** Converts the NameSet to a String */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	synchronized (this) {
		Iterator it = data.values().iterator();
		while (it.hasNext()) {
			Object typelist = it.next();
			Object [] elements = lookupAll(typelist);
			for (int i = 0; i < elements.length; i++) {
				sb.append(elements[i]);
				sb.append("\n");
			}
		}
	}
	return sb.toString();
}
	
}

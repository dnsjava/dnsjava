// Copyright (c) 1999-2001 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The shared superclass of Zone and Cache.  All names are stored in a
 * hashtable.  Each name contains a hashtable indexed by type.
 *
 * @author Brian Wellington
 */

class NameSet {

private Hashtable data;
private Name origin;
private boolean isCache;

/** Creates an empty NameSet for use as a Zone or Cache.  The origin is set
 * to the root.
 */
protected
NameSet(boolean isCache) {
	data = new Hashtable();
	origin = Name.root;
	this.isCache = isCache;
}

/** Sets the origin of the NameSet */
protected void
setOrigin(Name origin) {
	this.origin = origin;
}

/** Deletes all sets in a NameSet */
protected void
clear() {
	data = new Hashtable();
}

/**
 * Finds all matching sets or something that causes the lookup to stop.
 */
protected Object
findSets(Name name, short type) {
	Object bestns = null;
	Object o;
	Name tname;
	int labels;
	int olabels;
	int tlabels;

	if (!name.subdomain(origin))
		return null;
	labels = name.labels();
	olabels = origin.labels();

	for (tlabels = olabels; tlabels <= labels; tlabels++) {
		if (tlabels == olabels)
			tname = origin;
		else if (tlabels == labels)
			tname = name;
		else
			tname = new Name(name, labels - tlabels);
		TypeMap nameInfo = findName(tname);
		if (nameInfo == null)
			continue;

		/* If this is an ANY lookup, return everything. */
		if (tlabels == labels && type == Type.ANY)
			return nameInfo.getAll();

		/* Look for an NS */
		if (tlabels > olabels || isCache) {
			o = nameInfo.get(Type.NS);
			if (o != null) {
				if (isCache)
					bestns = o;
				else
					return o;
			}
		}

		/* If this is the name, look for the actual type. */
		if (tlabels == labels) {
			o = nameInfo.get(type);
			if (o != null)
				return o;
		}

		/* Look for a CNAME */
		o = nameInfo.get(Type.CNAME);
		if (o != null) {
			if (labels == tlabels)
				return o;
			else
				return null;
		}

		/* Look for a DNAME, unless this is the actual name */
		if (tlabels < labels) {
			o = nameInfo.get(Type.DNAME);
			if (o != null)
				return o;
		}

		/*
		 * If this is the name and this is a cache, look for an
		 * NXDOMAIN entry.
		 */
		if (tlabels == labels && isCache) {
			o = nameInfo.get((short)0);
			if (o != null)
				return o;
		}

		/*
		 * If this is the name and we haven't matched anything,
		 * just return the name.
		 */
		if (tlabels == labels)
			return nameInfo;
	}
	if (bestns == null)
		return null;
	else
		return bestns;
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
 * Removes the given set with the name and type.  The data contained in the
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
		Object [] elements = nameInfo.getAll();
		if (elements == null)
			continue;
		for (int i = 0; i < elements.length; i++)
			sb.append(elements[i]);
	}
	return sb.toString();
}
	
}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import java.io.*;

/**
 * A set of Records with the same name, type, and class.  Also included
 * are all SIG records signing the data records.
 * @see Record
 * @see SIGRecord
 *
 * @author Brian Wellington
 */

public class RRset implements TypedObject {

private List rrs;
private List sigs;
private int start;
private byte securityStatus;

/** Creates an empty RRset */
public
RRset() {
	rrs = new ArrayList(1);
	sigs = null;
	start = 0;
	securityStatus = DNSSEC.Insecure;
}

/** Adds a Record to an RRset */
public void
addRR(Record r) {
	if (r.getType() != Type.SIG) {
		synchronized (rrs) {
			if (!rrs.contains(r))
				rrs.add(r);
			start = 0;
		}
	}
	else {
		if (sigs == null)
			sigs = new ArrayList();
		if (!sigs.contains(r))
			sigs.add(r);
	}
}

/** Deletes a Record from an RRset */
public void
deleteRR(Record r) {
	if (r.getType() != Type.SIG) {
		synchronized (rrs) {
			rrs.remove(r);
			start = 0;
		}
	}
	else if (sigs != null)
		sigs.remove(r);
}

/** Deletes all Records from an RRset */
public void
clear() {
	synchronized (rrs) {
		rrs.clear();
		start = 0;
	}
	sigs = null;
}

/**
 * Returns an Iterator listing all (data) records.  This cycles through
 * the records, so each Iterator will start with a different record.
 */
public synchronized Iterator
rrs() {
	int size = rrs.size();
	if (size == 0)
		return Collections.EMPTY_LIST.iterator();
	if (start == size)
		start = 0;
	if (start++ == 0)
		return (rrs.iterator());
	List list = new ArrayList(rrs.subList(start - 1, size));
	list.addAll(rrs.subList(0, start - 1));
	return list.iterator();
}

/** Returns an Iterator listing all signature records */
public Iterator
sigs() {
	if (sigs == null)
		return Collections.EMPTY_LIST.iterator();
	else
		return sigs.iterator();
}

/** Returns the number of (data) records */
public int
size() {
	return rrs.size();
}

/**
 * Returns the name of the records
 * @see Name
 */
public Name
getName() {
	Record r = first();
	if (r == null)
		return null;
	return r.getName();
}

/**
 * Returns the type of the records
 * @see Type
 */
public int
getType() {
	Record r = first();
	if (r == null)
		return 0;
	return r.getType();
}

/**
 * Returns the class of the records
 * @see DClass
 */
public int
getDClass() {
	Record r = first();
	if (r == null)
		return 0;
	return r.getDClass();
}

/** Returns the ttl of the records */
public int
getTTL() {
	synchronized (rrs) {
		if (rrs.size() == 0)
			return 0;
		int ttl = Integer.MAX_VALUE;
		Iterator it = rrs.iterator();
		while (it.hasNext()) {
			Record r = (Record)it.next();
			if (r.getTTL() < ttl)
				ttl = r.getTTL();
		}
		return (ttl);
	}
}

/** Returns the first record */
public Record
first() {
	try {
		return (Record) rrs.get(0);
	}
	catch (IndexOutOfBoundsException e) {
		return null;
	}
}

/** Sets the DNSSEC security of the RRset. */
void
setSecurity(byte status) {
	securityStatus = status;
}

/** Returns the DNSSEC security of the RRset. */
public byte
getSecurity() {
	return securityStatus;
}

private String
iteratorToString(Iterator it) {
	StringBuffer sb = new StringBuffer();
	while (it.hasNext()) {
		Record rr = (Record) it.next();
		sb.append("[");
		sb.append(rr.rdataToString());
		sb.append("]");
		if (it.hasNext())
			sb.append(" ");
	}
	return sb.toString();
}

/** Converts the RRset to a String */
public String
toString() {
	if (rrs == null)
		return ("{empty}");
	StringBuffer sb = new StringBuffer();
	sb.append("{ ");
	sb.append(getName() + " ");
	sb.append(getTTL() + " ");
	sb.append(DClass.string(getDClass()) + " ");
	sb.append(Type.string(getType()) + " ");
	sb.append(iteratorToString(rrs.iterator()));
	if (sigs != null) {
		sb.append(" sigs: ");
		sb.append(iteratorToString(sigs.iterator()));
	}
	sb.append(" }");
	return sb.toString();
}

}

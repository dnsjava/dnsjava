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

public class RRset {

class Enumerator implements Enumeration {
	int count;
	Record [] records;

	Enumerator() {
		synchronized (rrs) {
			int size = rrs.size();
			records = new Record[size];
			if (size == 0)
				return;
			start++;
			while (start >= size)
				start -= size;
			int i = 0;
			for (int j = start; j < size; j++)
				records[i++] = (Record) rrs.elementAt(j);
			for (int j = 0; j < start; j++)
				records[i++] = (Record) rrs.elementAt(j);
		}
	}

	public boolean
	hasMoreElements() {
		return (count < records.length);
	}

	public Object
	nextElement() {
		if (count == records.length)
			throw new NoSuchElementException();
		return records[count++];
	}
}

private Vector rrs;
private Vector sigs;
private int start;
private byte securityStatus;

/** Creates an empty RRset */
public
RRset() {
	rrs = new Vector();
	sigs = new Vector();
	start = 0;
	securityStatus = DNSSEC.Insecure;
}

/** Adds a Record to an RRset */
public void
addRR(Record r) {
	if (r.getType() != Type.SIG) {
		synchronized (rrs) {
			if (!rrs.contains(r))
				rrs.addElement(r);
		}
	}
	else {
		if (!sigs.contains(r))
			sigs.addElement(r);
	}
}

/** Deletes a Record from an RRset */
public void
deleteRR(Record r) {
	if (r.getType() != Type.SIG) {
		synchronized (rrs) {
			rrs.removeElement(r);
		}
	}
	else
		sigs.removeElement(r);
}

/** Deletes all Records from an RRset */
public void
clear() {
	synchronized (rrs) {
		rrs.setSize(0);
	}
	sigs.setSize(0);
	start = 0;
}

/**
 * Returns an Enumeration listing all (data) records.  This cycles through
 * the records, so each Enumeration will start with a different record.
 */
public Enumeration
rrs() {
	return new Enumerator();
}

/** Returns an Enumeration listing all signature records */
public Enumeration
sigs() {
	return sigs.elements();
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
	if (rrs.size() == 0)
		return null;
	Record r =  (Record) rrs.elementAt(0);
	return r.getName();
}

/**
 * Returns the type of the records
 * @see Type
 */
public short
getType() {
	if (rrs.size() == 0)
		return 0;
	Record r =  (Record) rrs.elementAt(0);
	return r.getType();
}

/**
 * Returns the class of the records
 * @see DClass
 */
public short
getDClass() {
	if (rrs.size() == 0)
		return 0;
	Record r =  (Record) rrs.elementAt(0);
	return r.getDClass();
}

/** Returns the ttl of the records */
public int
getTTL() {
	if (rrs.size() == 0)
		return 0;
	int ttl = Integer.MAX_VALUE;
	Enumeration e = rrs();
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (r.getTTL() < ttl)
			ttl = r.getTTL();
	}
	return ttl;
}

/** Returns the first record */
public Record
first() {
	if (rrs.size() == 0)
		return null;
	return (Record) rrs.elementAt(0);
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

/** Converts the RRset to a String */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append("{ [");
	Enumeration e = new Enumerator();
	while (e.hasMoreElements()) {
		Record rr = (Record) e.nextElement();
		sb.append(rr);
		if (e.hasMoreElements())
			sb.append("<>");
	}
	sb.append("] [");
	e = sigs();
	while (e.hasMoreElements()) {
		Record rr = (Record) e.nextElement();
		sb.append(rr);
		if (e.hasMoreElements())
			sb.append("<>");
	}
	sb.append("] }");
	return sb.toString();
}

}

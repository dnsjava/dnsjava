// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

/**
 * A set of Records with the same name, type, and class.  Also included
 * are all SIG records signing the data records.
 * @see Record
 * @see SIGRecord
 */

public class RRset {

private Vector rrs;
private Vector sigs;

/** Creates an empty RRset */
public
RRset() {
	rrs = new Vector();
	sigs = new Vector();
}

/** Adds a Record to an RRset */
public void
addRR(Record r) {
	if (r.getType() != Type.SIG) {
		if (!rrs.contains(r))
			rrs.addElement(r);
	}
	else {
		if (!sigs.contains(r))
			sigs.addElement(r);
	}
}

/** Deletes all Records from an RRset */
public void
clear() {
	rrs.setSize(0);
	sigs.setSize(0);
}

/** Returns an Enumeration listing all (data) records */
public Enumeration
rrs() {
	return rrs.elements();
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
 * see @Name
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
 * see @Type
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
 * see @DClass
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

/** Converts the RRset to a String */
public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append("{ [");
	Enumeration e = rrs();
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

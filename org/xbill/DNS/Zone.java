// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A DNS Zone.  This encapsulates all data related to a Zone, and provides
 * convenient lookup methods.
 *
 * @author Brian Wellington
 */

public class Zone extends NameSet {

class AXFRIterator implements Iterator {
	private Iterator znames;
	private Name currentName;
	private Object [] current;
	int count;
	boolean sentFirstSOA, sentNS, sentOrigin, sentLastSOA;

	AXFRIterator() {
		znames = names();
	}

	public boolean
	hasNext() {
		return (!sentLastSOA);
	}

	public Object
	next() {
		if (sentLastSOA)
			return null;
		if (!sentFirstSOA) {
			sentFirstSOA = true;
			return (RRset) findExactSet(origin, Type.SOA);
		}
		if (!sentNS) {
			sentNS = true;
			return getNS();
		}
		if (!sentOrigin) {
			if (currentName == null) {
				currentName = getOrigin();
				current = findExactSets(currentName);
				count = 0;
			}
			while (count < current.length) {
				RRset rrset = (RRset) current[count];
				if (rrset.getType() != Type.SOA &&
				    rrset.getType() != Type.NS)
					return current[count++];
				count++;
			}
			current = null;
			sentOrigin = true;
		}
		if (current != null && count < current.length)
			return current[count++];
		while (znames.hasNext()) {
			Name currentName = (Name) znames.next();
			if (currentName.equals(getOrigin()))
				continue;
			current = findExactSets(currentName);
			count = 0;
			if (count < current.length)
				return current[count++];
		}
		sentLastSOA = true;
		RRset rrset = new RRset();
		rrset.addRR(getSOA());
		return rrset;
	}

	public void
	remove() {
		throw new UnsupportedOperationException();
	}
}

/** A primary zone */
public static final int PRIMARY = 1;

/** A secondary zone */
public static final int SECONDARY = 2;

private int type;
private Name origin;
private short dclass = DClass.IN;
private RRset NS;
private SOARecord SOA;
private boolean hasWild;

private void
validate() throws IOException {
	RRset rrset = (RRset) findExactSet(origin, Type.SOA);
	if (rrset == null || rrset.size() != 1)
		throw new IOException(origin +
				      ": exactly 1 SOA must be specified");
	Iterator it = rrset.rrs();
	SOA = (SOARecord) it.next();
	NS = (RRset) findExactSet(origin, Type.NS);
	if (NS == null)
		throw new IOException(origin + ": no NS set specified");
}

private final void
maybeAddRecord(Record record, Cache cache, Object source) throws IOException {
	int type = record.getType();
	Name name = record.getName();

	if (type == Type.SOA) {
		if (!name.equals(origin))
			throw new IOException("SOA owner " + name +
					      " does not match zone origin " +
					      origin);
		else {
			setOrigin(origin);
			dclass = record.getDClass();
		}
	}
	if (origin == null && type != Type.SOA)
		throw new IOException("non-SOA record seen at " +
				      name + " with no origin set");
	if (name.subdomain(origin))
		addRecord(record);
	else if (cache != null)
		cache.addRecord(record, Credibility.GLUE, source);
}

/**
 * Creates a Zone from the records in the specified master file.  All
 * records that do not belong in the Zone are added to the specified Cache.
 * @see Cache
 * @see Master
 */
public
Zone(String file, Cache cache, Name initialOrigin) throws IOException {
	super(false);
	Master m = new Master(file, initialOrigin);
	Record record;

	origin = initialOrigin;
	while ((record = m.nextRecord()) != null)
		maybeAddRecord(record, cache, file);
	validate();
}

/**
 * Creates a Zone from an array of records.  All records that do not belong
 * in the Zone are added to the specified Cache.
 * @see Cache
 * @see Master
 */
public
Zone(Record [] records, Cache cache, Name initialOrigin) throws IOException {
	super(false);

	origin = initialOrigin;
	for (int i = 0; i < records.length; i++) {
		maybeAddRecord(records[i], cache, records);
	}
	validate();
}

/**
 * Creates a Zone from the records in the specified master file.  All
 * records that do not belong in the Zone are added to the specified Cache.
 * @see Cache
 * @see Master
 */
public
Zone(String file, Cache cache) throws IOException {
	this(file, cache, null);
}

/**
 * Creates a Zone by performing a zone transfer to the specified host.  All
 * records that do not belong in the Zone are added to the specified Cache.
 * @see Cache
 * @see Master
 */
public
Zone(Name zone, short dclass, String remote, Cache cache) throws IOException {
	super(false);
	origin = zone;
	this.dclass = dclass;
	type = SECONDARY;
	Resolver res = new SimpleResolver(remote);
	Record rec = Record.newRecord(zone, Type.AXFR, dclass);
	Message query = Message.newQuery(rec);
	Message response = res.send(query);
	short rcode = response.getHeader().getRcode();
	if (rcode != Rcode.NOERROR)
		throw new IOException("AXFR failed: " + Rcode.string(rcode));
	Record [] recs = response.getSectionArray(Section.ANSWER);
	for (int i = 0; i < recs.length; i++) {
		if (!recs[i].getName().subdomain(origin)) {
			if (Options.check("verbose"))
				System.err.println(recs[i].getName() +
						   "is not in zone " + origin);
			continue;
		}
		addRecord(recs[i]);
	}
	if (cache != null) {
		recs = response.getSectionArray(Section.ADDITIONAL);
		for (int i = 0; i < recs.length; i++)
			cache.addRecord(recs[i], Credibility.GLUE, recs);
	}
	validate();
}

/** Returns the Zone's origin */
public Name
getOrigin() {
	return origin;
}

/** Returns the Zone origin's NS records */
public RRset
getNS() {
	return NS;
}

/** Returns the Zone's SOA record */
public SOARecord
getSOA() {
	return SOA;
}

/** Returns the Zone's class */
public short
getDClass() {
	return dclass;
}

/**     
 * Looks up Records in the Zone.  This follows CNAMEs and wildcards.
 * @param name The name to look up
 * @param type The type to look up
 * @return A SetResponse object
 * @see SetResponse
 */ 
public SetResponse
findRecords(Name name, short type) {
	SetResponse zr = null;

	Object o = lookup(name, type);
	if (o == null) {
		/* The name does not exist */
		if (name.isWild() || !hasWild)
			return SetResponse.ofType(SetResponse.NXDOMAIN);

		int labels = name.labels() - origin.labels();
		SetResponse sr;
		Name tname = name;
		do {
			sr = findRecords(tname.wild(1), type);
			if (!sr.isNXDOMAIN())
				return sr;
			tname = new Name(tname, 1);
		} while (labels-- >= 1);
		return SetResponse.ofType(SetResponse.NXDOMAIN);
	} else if (o == NXRRSET) {
		/* The name exists but the type does not. */
		return SetResponse.ofType(SetResponse.NXRRSET);
	}

	Object [] objects;
	RRset rrset;

	if (o instanceof RRset) {
		objects = null;
		rrset = (RRset) o;
	}
	else {
		objects = (Object []) o;
		rrset = (RRset) objects[0];
	}

	if (name.equals(rrset.getName())) {
		if (type != Type.CNAME && type != Type.ANY &&
		    rrset.getType() == Type.CNAME)
			zr = new SetResponse(SetResponse.CNAME, rrset);
		else if (rrset.getType() == Type.NS &&
			 !name.equals(origin))
			zr = new SetResponse(SetResponse.DELEGATION, rrset);
		else {
			zr = new SetResponse(SetResponse.SUCCESSFUL);
			zr.addRRset(rrset);
			if (objects != null) {
				for (int i = 1; i < objects.length; i++)
					zr.addRRset((RRset)objects[i]);
			}
		}
	} else {
		if (rrset.getType() == Type.CNAME)
			zr = SetResponse.ofType(SetResponse.NXDOMAIN);
		else if (rrset.getType() == Type.DNAME)
			zr = new SetResponse(SetResponse.DNAME, rrset);
		else if (rrset.getType() == Type.NS)
			zr = new SetResponse(SetResponse.DELEGATION, rrset);
	}
	return zr;
}

/**
 * Looks up Records in the zone, finding exact matches only.
 * @param name The name to look up
 * @param type The type to look up
 * @return The matching RRset
 * @see RRset
 */ 
public RRset
findExactMatch(Name name, short type) {
	return (RRset) findExactSet(name, type);
}

/**
 * Adds a record to the Zone
 * @param r The record to be added
 * @see Record
 */
public void
addRecord(Record r) {
	Name name = r.getName();
	short type = r.getRRsetType();
	RRset rrset = (RRset) findExactSet (name, type);
	if (rrset == null)
		addSet(name, type, rrset = new RRset());
	rrset.addRR(r);
}

/**
 * Adds a set associated with a name/type.  The data contained in the
 * set is abstract.
 */
protected void
addSet(Name name, short type, TypedObject set) {
	if (!hasWild && name.isWild())
		hasWild = true;
	super.addSet(name, type, set);
}

/**
 * Removes a record from the Zone
 * @param r The record to be removed
 * @see Record
 */
public void
removeRecord(Record r) {
	Name name = r.getName();
	short type = r.getRRsetType();
	RRset rrset = (RRset) findExactSet (name, type);
	if (rrset != null) {
		rrset.deleteRR(r);
		if (rrset.size() == 0)
			removeSet(name, type, rrset);
	}
}

/**
 * Returns an Iterator containing the RRsets of the zone that can be used
 * to construct an AXFR.
 */
public Iterator
AXFR() {
	return new AXFRIterator();
}

/**
 * Returns the contents of a Zone in master file format.
 */
public String
toMasterFile() {
	Iterator znames = names();
	StringBuffer sb = new StringBuffer();
	while (znames.hasNext()) {
		Name name = (Name) znames.next();
		Object [] sets = findExactSets(name);
		for (int i = 0; i < sets.length; i++) {
			RRset rrset = (RRset) sets[i];
			Iterator it = rrset.rrs();
			while (it.hasNext())
				sb.append(it.next() + "\n");
			it = rrset.sigs();
			while (it.hasNext())
				sb.append(it.next() + "\n");
		}
	}
	return sb.toString();
}

}

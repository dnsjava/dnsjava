// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

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

class ZoneIterator implements Iterator {
	private Iterator znames;
	private Name nextName;
	private Object [] current;
	int count;
	boolean wantLastSOA;

	ZoneIterator(boolean axfr) {
		znames = names();
		wantLastSOA = axfr;
		Object [] sets = findExactSets(origin);
		current = new Object[sets.length];
		for (int i = 0, j = 2; i < sets.length; i++) {
			int type = ((RRset) sets[i]).getType();
			if (type == Type.SOA)
				current[0] = sets[i];
			else if (type == Type.NS)
				current[1] = sets[i];
			else
				current[j++] = sets[i];
		}
	}

	public boolean
	hasNext() {
		return (current != null || wantLastSOA);
	}

	public Object
	next() {
		if (!hasNext()) {
			throw new NoSuchElementException();
		}
		if (current == null && wantLastSOA) {
			wantLastSOA = false;
			return (RRset) findExactSet(origin, Type.SOA);
		}
		Object set = current[count++];
		if (count == current.length) {
			nextName = null;
			current = null;
			while (znames.hasNext()) {
				Name name = (Name) znames.next();
				if (name.equals(origin))
					continue;
				Object [] sets = findExactSets(name);
				if (sets.length == 0)
					continue;
				nextName = name;
				current = sets;
				count = 0;
				break;
			}
		}
		return set;
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
private int dclass = DClass.IN;
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

	if (origin == null) {
		if (type == Type.SOA) {
			origin = name;
			setOrigin(origin);
		} else {
			throw new IOException("non-SOA record seen at " +
					      name + " with no origin set");
		}
	}
	if (type == Type.SOA && !name.equals(origin)) {
		throw new IOException("SOA owner " + name +
				      " does not match zone origin " +
				      origin);
	}
	if (name.subdomain(origin))
		addRecord(record);
	else if (cache != null)
		cache.addRecord(record, Credibility.GLUE, source);
}

/**
 * Creates a Zone from the records in the specified master file.  All
 * records that do not belong in the Zone are added to the specified Cache,
 * if the Cache is not null.
 * @see Cache
 * @see Master
 */
public
Zone(String file, Cache cache, Name initialOrigin) throws IOException {
	super(false);
	Master m = new Master(file, initialOrigin);
	Record record;

	origin = initialOrigin;
	if (origin != null)
		setOrigin(origin);
	while ((record = m.nextRecord()) != null)
		maybeAddRecord(record, cache, file);
	validate();
}

/**
 * Creates a Zone from an array of records.  All records that do not belong
 * in the Zone are added to the specified Cache, if the Cache is not null.
 * @see Cache
 * @see Master
 */
public
Zone(Record [] records, Cache cache, Name initialOrigin) throws IOException {
	super(false);

	origin = initialOrigin;
	if (origin != null)
		setOrigin(origin);
	for (int i = 0; i < records.length; i++) {
		maybeAddRecord(records[i], cache, records);
	}
	validate();
}

/**
 * Creates a Zone from the records in the specified master file.  All
 * records that do not belong in the Zone are added to the specified Cache,
 * if the Cache is not null.
 * @see Cache
 * @see Master
 */
public
Zone(String file, Cache cache) throws IOException {
	this(file, cache, null);
}

public void
fromXFR(Name zone, int dclass, String remote)
throws IOException, ZoneTransferException
{
	if (!zone.isAbsolute())
		throw new RelativeNameException(zone);
	DClass.check(dclass);

	origin = zone;
	setOrigin(origin);
	this.dclass = dclass;
	type = SECONDARY;
	ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(zone, remote, null);
	List records = xfrin.run();
	for (Iterator it = records.iterator(); it.hasNext(); ) {
		Record rec = (Record) it.next();
		if (!rec.getName().subdomain(origin)) {
			if (Options.check("verbose"))
				System.err.println(rec.getName() +
						   "is not in zone " + origin);
			continue;
		}
		addRecord(rec);
	}
	validate();
}

/**
 * Creates a Zone by performing a zone transfer to the specified host.
 * @see Master
 */
public
Zone(Name zone, int dclass, String remote)
throws IOException, ZoneTransferException
{
	super(false);
	fromXFR(zone, dclass, remote);
}

/**
 * Creates a Zone by performing a zone transfer to the specified host.
 * The cache is unused.
 * @see Master
 */
public
Zone(Name zone, int dclass, String remote, Cache cache) throws IOException {
	super(false);
	DClass.check(dclass);
	try {
		fromXFR(zone, dclass, remote);
	}
	catch (ZoneTransferException e) {
		throw new IOException(e.getMessage());
	}
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
public int
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
findRecords(Name name, int type) {
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
findExactMatch(Name name, int type) {
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
	int type = r.getRRsetType();
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
addSet(Name name, int type, TypedObject set) {
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
	int type = r.getRRsetType();
	RRset rrset = (RRset) findExactSet (name, type);
	if (rrset != null) {
		rrset.deleteRR(r);
		if (rrset.size() == 0)
			removeSet(name, type, rrset);
	}
}

/**
 * Returns an Iterator over the RRsets in the zone.
 */
public Iterator
iterator() {
	return new ZoneIterator(false);
}

/**
 * Returns an Iterator over the RRsets in the zone that can be used to
 * construct an AXFR response.  This is identical to {@link #iterator} except
 * that the SOA is returned at the end as well as the beginning.
 */
public Iterator
AXFR() {
	return new ZoneIterator(true);
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

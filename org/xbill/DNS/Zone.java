// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A DNS Zone.  This encapsulates all data related to a Zone, and provides
 * convienient lookup methods.
 *
 * @author Brian Wellington
 */

public class Zone extends NameSet {

/** A primary zone */
public static final int PRIMARY = 1;

/** A secondary zone (unimplemented) */
public static final int SECONDARY = 2;

private int type;
private Name origin;
private short dclass = DClass.IN;

/**
 * Creates a Zone from the records in the specified master file.  All
 * records that do not belong in the Zone are added to the specified Cache.
 * @see Cache
 * @see Master
 */
public
Zone(String file, Cache cache) throws IOException {
	super();
	type = PRIMARY;
	Master m = new Master(file);
	
	Record record;

	while ((record = m.nextRecord()) != null) {
		if (origin == null || record.getName().subdomain(origin)) {
			addRecord(record);
			if (origin == null && record.getType() == Type.SOA)
				origin = record.getName();
		}
		else
			cache.addRecord(record, Credibility.ZONE_GLUE, m);
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
	return (RRset) findExactSet(origin, Type.NS, dclass);
}

/** Returns the Zone's SOA record */
public SOARecord
getSOA() {
	RRset rrset = (RRset) findExactSet(origin, Type.SOA, dclass);
	if (rrset == null)
		return null;
	Enumeration e = rrset.rrs();
	return (SOARecord) e.nextElement();
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

	if (findName(name) == null) {
		if (name.isWild())
			return new SetResponse(SetResponse.NXDOMAIN);
		else
			return findRecords(name.wild(), type);
	}
	Object [] objects = findSets(name, type, dclass);
	if (objects == null)
		return new SetResponse(SetResponse.NODATA);

	RRset [] rrsets = new RRset[objects.length];
	System.arraycopy(objects, 0, rrsets, 0, objects.length);

	for (int i = 0; i < rrsets.length; i++) {
		RRset rrset = rrsets[i];

		if (type != Type.CNAME && type != Type.ANY &&
		    rrset.getType() == Type.CNAME)
		{
			CNAMERecord cname = (CNAMERecord) rrset.first();
			zr = findRecords(cname.getTarget(), type);
			if (zr.isNODATA())
				zr.set(SetResponse.PARTIAL, cname);
			else if (zr.isNXDOMAIN() &&
				 !cname.getTarget().subdomain(origin))
				zr.set(SetResponse.PARTIAL, cname);
			zr.addCNAME(cname);
			return zr;
		}
		if (zr == null)
			zr = new SetResponse(SetResponse.SUCCESSFUL);
		zr.addRRset(rrset);
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
	return (RRset) findExactSet(name, type, dclass);
}

/**
 * Adds a record to the Zone
 * @param r The record to be added
 * @see Record
 */
public void
addRecord(Record r) {
	Name name = r.getName();
	short type = r.getType();
	RRset rrset = (RRset) findExactSet (name, type, dclass);
	if (rrset == null)
		addSet(name, type, dclass, rrset = new RRset());
	rrset.addRR(r);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;

public class Zone extends NameSet {

public static final int CACHE = 1;
public static final int PRIMARY = 2;
public static final int SECONDARY = 3;

private int type;
private Name origin;
private short dclass = DClass.IN;

public
Zone(String file, Cache cache) throws IOException {
	super();
	type = PRIMARY;
	Master m = new Master(file);
	
	Record record;

	while ((record = m.nextRecord()) != null) {
		if (origin == null || record.getName().subdomain(origin)) {
			addRR(record);
			if (origin == null && record.getType() == Type.SOA)
				origin = record.getName();
		}
		else
			cache.addRecord(record, Credibility.ZONE_GLUE, m);
	}
}

public Name
getOrigin() {
	return origin;
}

public RRset
getNS() {
	return (RRset) findExactSet(origin, Type.NS, dclass);
}

public SOARecord
getSOA() {
	RRset rrset = (RRset) findExactSet(origin, Type.SOA, dclass);
	if (rrset == null)
		return null;
	Enumeration e = rrset.rrs();
	return (SOARecord) e.nextElement();
}

public short
getDClass() {
	return dclass;
}

public ZoneResponse
findRecords(Name name, short type) {
	ZoneResponse zr = null;

	if (findName(name) == null)
		return new ZoneResponse(ZoneResponse.NXDOMAIN);
	Object [] objects = findSets(name, type, dclass);
	if (objects == null)
		return new ZoneResponse(ZoneResponse.NODATA);

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
				zr.set(ZoneResponse.PARTIAL, cname);
			else if (zr.isNXDOMAIN() &&
				 !cname.getTarget().subdomain(origin))
				zr.set(ZoneResponse.PARTIAL, cname);
			zr.addCNAME(cname);
			return zr;
		}
		if (zr == null)
			zr = new ZoneResponse(ZoneResponse.SUCCESSFUL);
		zr.addRRset(rrset);
	}
	return zr;
}

public RRset
findExactMatch(Name name, short type) {
	return (RRset) findExactSet(name, type, dclass);
}

public void
addRR(Record record) {
	Name name = record.getName();
	short type = record.getType();
	RRset rrset = (RRset) findExactSet (name, type, dclass);
	if (rrset == null)
		addSet(name, type, dclass, rrset = new RRset());
	rrset.addRR(record);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

public class Cache extends NameSet {

private class Element {
	RRset rrset;
	byte credibility;
	long timeIn;
	int ttl;
	int srcid;

	public
	Element(int _ttl, byte cred, int src) {
		rrset = null;
		credibility = cred;
		ttl = _ttl;
		srcid = src;
		timeIn = System.currentTimeMillis();
	}
	public
	Element(Record r, byte cred, int src) {
		rrset = new RRset();
		credibility = cred;
		ttl = -1;
		srcid = src;
		update(r);
	}

	public
	Element(RRset r, byte cred, int src) {
		rrset = r;
		credibility = cred;
		ttl = -1;
		timeIn = System.currentTimeMillis();
		ttl = r.getTTL();
		srcid = src;
	}

	public void
	update(Record r) {
		rrset.addRR(r);
		timeIn = System.currentTimeMillis();
		if (ttl < 0)
			ttl = r.getTTL();
	}

	public boolean
	expiredTTL() {
		return (System.currentTimeMillis() > timeIn + (1000 * ttl));
	}

	public String
	toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(rrset);
		sb.append(" cl = ");
		sb.append(credibility);
		return sb.toString();
	}
}

public
Cache() {
	super();
}

public
Cache(String file) throws IOException {
	Master m = new Master(file);
	Record record;
	while ((record = m.nextRecord()) != null) {
		addRecord(record, Credibility.HINT, m);
	}
}

public void
addRecord(Record r, byte cred, Object o) {
	Name name = r.getName();
	short type = r.getRRsetType();
	short dclass = r.getDClass();
	if (!Type.isRR(type))
		return;
	int src = (o != null) ? o.hashCode() : 0;
	if (r.getTTL() == 0)
		return;
	Element element = (Element) findExactSet(name, type, dclass);
	if (element == null || cred > element.credibility)
		addSet(name, type, dclass,
		       element = new Element(r, cred, src));
	else if (cred == element.credibility) {
		if (element.srcid != src)
			element.rrset.clear();
		element.update(r);
	}
}

public void
addRRset(RRset rrset, byte cred, Object o) {
	Name name = rrset.getName();
	short type = rrset.getType();
	short dclass = rrset.getDClass();
	int src = (o != null) ? o.hashCode() : 0;
	if (rrset.getTTL() == 0)
		return;
	Element element = (Element) findExactSet(name, type, dclass);
	if (element == null || cred > element.credibility)
		addSet(name, type, dclass, new Element(rrset, cred, src));
}

public void
addNegative(Name name, short type, short dclass, int ttl, byte cred, Object o) {
	int src = (o != null) ? o.hashCode() : 0;
	Element element = (Element) findExactSet(name, type, dclass);
	if (element == null || cred > element.credibility)
		addSet(name, type, dclass, new Element(ttl, cred, src));
}

public CacheResponse
lookupRecords(Name name, short type, short dclass, byte minCred) {
	CacheResponse cr = null;
	Object [] objects = findSets(name, type, dclass);

	if (objects == null)
		return new CacheResponse(CacheResponse.UNKNOWN);

	int nelements = 0;
	for (int i = 0; i < objects.length; i++) {
		Element element = (Element) objects[i];
		if (element.expiredTTL()) {
			removeSet(name, type, dclass, element);
			objects[i] = null;
		}
		else if (element.credibility < minCred)
			objects[i] = null;
		else
			nelements++;
	}
	if (nelements == 0)
		return new CacheResponse(CacheResponse.UNKNOWN);

	Element [] elements = new Element[nelements];
	for (int i = 0, j = 0; i < objects.length; i++) {
		if (objects[i] == null)
			continue;
		elements[j++] = (Element) objects[i];
	}

	for (int i = 0; i < elements.length; i++) {
		if (elements[i] == null)
			continue;

		RRset rrset = elements[i].rrset;
		if (rrset == null) {
			if (type == Type.ANY)
				continue;
			return new CacheResponse(CacheResponse.NEGATIVE);
		}

		if (type != Type.CNAME && type != Type.ANY &&
		    rrset.getType() == Type.CNAME)
		{
			CNAMERecord cname = (CNAMERecord) rrset.first();
			cr = lookupRecords(cname.getTarget(), type, dclass,
					   minCred);
			if (cr.isUnknown())
				cr.set(CacheResponse.PARTIAL, cname);
			cr.addCNAME(cname);
			return cr;
		}
		if (cr == null)
			cr = new CacheResponse(CacheResponse.SUCCESSFUL);
		cr.addRRset(rrset);	
	}
	return cr;
}

RRset []
findRecords(Name name, short type, short dclass, byte minCred) {
	CacheResponse cr = lookupRecords(name, type, dclass, minCred);
	if (cr.isSuccessful())
		return cr.answers();
	else
		return null;
}

public RRset []
findRecords(Name name, short type, short dclass) {
	return findRecords(name, type, dclass, Credibility.NONAUTH_ANSWER);
}

public RRset []
findAnyRecords(Name name, short type, short dclass) {
	return findRecords(name, type, dclass, Credibility.NONAUTH_ADDITIONAL);
}

public void
addMessage(Message in) {
	Enumeration e;
	boolean isAuth = in.getHeader().getFlag(Flags.AA);
	Name queryName = in.getQuestion().getName();
	short queryType = in.getQuestion().getType();
	short queryClass = in.getQuestion().getDClass();
	byte cred;
	short rcode = in.getHeader().getRcode();
	short ancount = in.getHeader().getCount(Section.ANSWER);

	if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN)
		return;

	e = in.getSection(Section.ANSWER);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth && r.getName().equals(queryName))
			cred = Credibility.AUTH_ANSWER;
		else if (isAuth)
			cred = Credibility.AUTH_NONAUTH_ANSWER;
		else
			cred = Credibility.NONAUTH_ANSWER;
		addRecord(r, cred, in);
	}

	if (ancount == 0 || rcode == Rcode.NXDOMAIN) {
		/* This is a negative response */
		SOARecord soa = null;
		e = in.getSection(Section.AUTHORITY);
		while (e.hasMoreElements()) {
			Record r = (Record) e.nextElement();
			if (r.getType() == Type.SOA) {
				soa = (SOARecord) r;
				break;
			}
		}
		if (isAuth)
			cred = Credibility.AUTH_AUTHORITY;
		else
			cred = Credibility.NONAUTH_AUTHORITY;
		if (soa != null) {
			int ttl = Math.min(soa.getTTL(), soa.getMinimum());
			if (ancount == 0)
				addNegative(queryName, queryType, queryClass,
					    ttl, cred, in);
			else {
				Record [] cnames;
				cnames = in.getSectionArray(Section.ANSWER);
				int last = cnames.length - 1;
				Name cname;
				cname = ((CNAMERecord)cnames[last]).getTarget();
				addNegative(cname, queryType, queryClass,
					    ttl, cred, in);
			}
		}
	}

	e = in.getSection(Section.AUTHORITY);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth)
			cred = Credibility.AUTH_AUTHORITY;
		else
			cred = Credibility.NONAUTH_AUTHORITY;
		addRecord(r, cred, in);
	}

	e = in.getSection(Section.ADDITIONAL);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth)
			cred = Credibility.AUTH_ADDITIONAL;
		else
			cred = Credibility.NONAUTH_ADDITIONAL;
		addRecord(r, cred, in);
	}
}

}

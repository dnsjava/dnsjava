// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

public class Cache extends NameSet {

private class CacheElement {
	RRset rrset;
	byte credibility;
	long timeIn;
	int ttl;
	int srcid;

	public
	CacheElement(int _ttl, byte cred, int src) {
		rrset = null;
		credibility = cred;
		ttl = _ttl;
		srcid = src;
		timeIn = System.currentTimeMillis();
	}
	public
	CacheElement(Record r, byte cred, int src) {
		rrset = new RRset();
		credibility = cred;
		ttl = -1;
		srcid = src;
		update(r);
	}

	public
	CacheElement(RRset r, byte cred, int src) {
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
	int src = (o != null) ? o.hashCode() : 0;
	if (r.getTTL() == 0)
		return;
	CacheElement element = (CacheElement) findSet(name, type);
	if (element == null || cred > element.credibility)
		addSet(name, type, element = new CacheElement(r, cred, src));
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
	int src = (o != null) ? o.hashCode() : 0;
	if (rrset.getTTL() == 0)
		return;
	CacheElement element = (CacheElement) findSet(name, type);
	if (element == null || cred > element.credibility)
		addSet(name, type, new CacheElement(rrset, cred, src));
}

public void
addNegative(Name name, short type, int ttl, byte cred, Object o) {
	int src = (o != null) ? o.hashCode() : 0;
	CacheElement element = (CacheElement) findSet(name, type);
	if (element == null || cred > element.credibility)
		addSet(name, type, new CacheElement(ttl, cred, src));
}

public CacheResponse
lookupRecords(Name name, short type, byte minCred) {
	CacheElement element = (CacheElement) findSet(name, type);
	if (element == null)
		return new CacheResponse(CacheResponse.UNKNOWN);
	if (element.expiredTTL()) {
		removeSet(name, type);
		return new CacheResponse(CacheResponse.UNKNOWN);
	}
	if (element.credibility >= minCred) {
		RRset rrset = element.rrset;
		if (rrset == null)
			return new CacheResponse(CacheResponse.NEGATIVE);
		if (type != Type.CNAME && rrset.getType() == Type.CNAME) {
			CNAMERecord cname;
			cname = (CNAMERecord) rrset.rrs().nextElement();
			CacheResponse cr;
			cr = lookupRecords(cname.getTarget(), type, minCred);
			if (!cr.isUnknown())
				return cr;
			else
				return new CacheResponse(CacheResponse.PARTIAL,
							 cname.getTarget());
		}
		else
			return new CacheResponse(CacheResponse.SUCCESSFUL,
						 rrset);
	}
	else
		return new CacheResponse(CacheResponse.UNKNOWN);
}

RRset
findRecords(Name name, short type, byte minCred) {
	CacheResponse cr = lookupRecords(name, type, minCred);
	if (cr.isSuccessful())
		return cr.answer();
	else
		return null;
}

public RRset
findRecords(Name name, short type) {
	return findRecords(name, type, Credibility.NONAUTH_ADDITIONAL);
}

public RRset
findAnyRecords(Name name, short type) {
	return findRecords(name, type, Credibility.NONAUTH_ADDITIONAL);
}

public void
addMessage(Message in) {
	Enumeration e;
	boolean isAuth = in.getHeader().getFlag(Flags.AA);
	Name queryName = in.getQuestion().getName();
	short queryType = in.getQuestion().getType();
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
				addNegative(queryName, queryType, ttl,
					    cred, in);
			else {
				Record [] cnames;
				cnames = in.getSectionArray(Section.ANSWER);
				int last = cnames.length - 1;
				Name cname;
				cname = ((CNAMERecord)cnames[last]).getTarget();
				addNegative(cname, queryType, ttl, cred, in);
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

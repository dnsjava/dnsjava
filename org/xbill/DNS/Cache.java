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

	public
	CacheElement(Record r, byte cred) {
		rrset = new RRset();
		rrset.addRR(r);
		credibility = cred;
	}

	public void
	update(Record r) {
		rrset.addRR(r);
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
Cache(String file) throws IOException {
	Master m = new Master(file);
	Record record;
	while ((record = m.nextRecord()) != null) {
		addRecord(record, Credibility.CACHE);
	}
}

public void
addRecord(Record r, byte cred) {
	Name name = r.getName();
	short type = r.getRRsetType();
	CacheElement element = (CacheElement) findSet(name, type);
	if (element == null || cred > element.credibility)
		addSet(name, type, element = new CacheElement(r, cred));
	else if (cred == element.credibility)
		element.update(r);
}

private RRset
findRecords(Name name, short type, byte minCred) {
	CacheElement element = (CacheElement) findSet(name, type);
	if (element.credibility >= minCred)
		return element.rrset;
	else
		return null;
}	

public RRset
findRecords(Name name, short type) {
	return findRecords(name, type, Credibility.NONAUTH_ANSWER);
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

	e = in.getSection(Section.ANSWER);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth) {
			if (r.getName().equals(queryName))
				addRecord(r, Credibility.AUTH_ANSWER);
			else
				addRecord(r, Credibility.AUTH_NONAUTH_ANSWER);
		}
		else
			addRecord(r, Credibility.NONAUTH_ANSWER);
	}

	e = in.getSection(Section.AUTHORITY);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth)
			addRecord(r, Credibility.AUTH_AUTHORITY);
		else
			addRecord(r, Credibility.NONAUTH_AUTHORITY);
	}

	e = in.getSection(Section.ADDITIONAL);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth)
			addRecord(r, Credibility.AUTH_ADDITIONAL);
		else
			addRecord(r, Credibility.NONAUTH_ADDITIONAL);
	}
}

}

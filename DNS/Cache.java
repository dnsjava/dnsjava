// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

public class Cache {

private class Set {
	RRset rrset;
	byte credibility;

	public
	Set(Record r, byte cred) {
		rrset = new RRset();
		rrset.addRR(r);
		credibility = cred;
	}

	public void
	update(Record r, byte cred) {
		rrset.addRR(r);
		credibility = cred;
	}
}

private Hashtable data;

static String defaultResolver = "localhost";

public
Cache() {
	data = new Hashtable();
}

void
addRecord(Record r, byte cred) {
	Name name = r.getName();
	short type = r.getRRsetType();
	Hashtable nameInfo = (Hashtable) data.get(name);
	if (nameInfo == null)
		data.put(name, nameInfo = new Hashtable());
	Set set = (Set) nameInfo.get(new Short(type));
	if (set == null) {
		nameInfo.put(new Short(type), set = new Set(r, cred));
	}
	else {
		if (cred < set.credibility)
			return;
		if (cred > set.credibility)
			set.rrset.clear();
		set.update(r, cred);
	}
}

public RRset
findRecords(Name name, short type) {
	Hashtable nameInfo = (Hashtable) data.get(name);
	if (nameInfo == null)
		return null;
	Set set = (Set) nameInfo.get(new Short(type));
	if (set == null)
		return null;
	return set.rrset;
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

public String
toString() {
	StringBuffer sb = new StringBuffer();
	Enumeration e = data.elements();
	while (e.hasMoreElements()) {
		Hashtable nameInfo = (Hashtable) e.nextElement();
		Enumeration e2 = nameInfo.elements();
		while (e2.hasMoreElements()) {
			Set s = (Set) e2.nextElement();
			sb.append(s.rrset.getName() + " " +
				  Type.string(s.rrset.getType()) +
				  " cl = " + s.credibility + "\n");
			Enumeration e3 = s.rrset.rrs();
			while (e3.hasMoreElements()) {
				sb.append(e3.nextElement());
				sb.append("\n");
			}
			e3 = s.rrset.sigs();
			while (e3.hasMoreElements()) {
				sb.append(e3.nextElement());
				sb.append("\n");
			}
		}
	}
	return sb.toString();
}
	
}

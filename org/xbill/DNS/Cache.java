// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * A cache of DNS records.  The cache obeys TTLs, so items are purged after
 * their validity period is complete.  Negative answers are cached, to
 * avoid repeated failed DNS queries.  The credibility of each RRset is
 * maintained, so that more credible records replace less credible records,
 * and lookups can specify the minimum credibility of data they are requesting.
 * @see RRset
 * @see Credibility
 *
 * @author Brian Wellington
 */

public class Cache extends NameSet {

private class Element {
	RRset rrset;
	byte credibility;
	long timeIn;
	int ttl;
	int srcid;
	Thread tid;

	public
	Element(int _ttl, byte cred, int src) {
		rrset = null;
		credibility = cred;
		ttl = _ttl;
		srcid = src;
		timeIn = System.currentTimeMillis();
		tid = Thread.currentThread();
	}
	public
	Element(Record r, byte cred, int src) {
		rrset = new RRset();
		credibility = cred;
		ttl = -1;
		srcid = src;
		update(r);
		tid = Thread.currentThread();
	}

	public
	Element(RRset r, byte cred, int src) {
		rrset = r;
		credibility = cred;
		ttl = -1;
		timeIn = System.currentTimeMillis();
		ttl = r.getTTL();
		srcid = src;
		tid = Thread.currentThread();
	}

	public void
	update(Record r) {
		rrset.addRR(r);
		timeIn = System.currentTimeMillis();
		if (ttl < 0)
			ttl = r.getTTL();
	}

	public void
	deleteRecord(Record r) {
		rrset.deleteRR(r);
	}

	public boolean
	expiredTTL() {
		long now = System.currentTimeMillis();
		long expire = timeIn + (1000 * (long)ttl);
		return (now > expire);
	}

	public boolean
	TTL0Ours() {
		return (ttl == 0 && tid == Thread.currentThread());
	}

	public boolean
	TTL0NotOurs() {
		return (ttl == 0 && tid != Thread.currentThread());
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

private Verifier verifier;
private boolean secure;

/** Creates an empty Cache */
public
Cache() {
	super();
}

/**
 * Creates a Cache which initially contains all records in the specified file
 */
public
Cache(String file) throws IOException {
	Master m = new Master(file);
	Record record;
	while ((record = m.nextRecord()) != null) {
		addRecord(record, Credibility.HINT, m);
	}
}

/**
 * Adds a record to the Cache
 * @param r The record to be added
 * @param cred The credibility of the record
 * @param o The source of the record (this could be a Message, for example)
 @ @see Record
 */
public void
addRecord(Record r, byte cred, Object o) {
	Name name = r.getName();
	short type = r.getRRsetType();
	short dclass = r.getDClass();
	if (!Type.isRR(type))
		return;
	int src = (o != null) ? o.hashCode() : 0;
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

/**
 * Adds an RRset to the Cache
 * @param r The RRset to be added
 * @param cred The credibility of these records
 * @param o The source of this RRset (this could be a Message, for example)
 * @see RRset
 */
public void
addRRset(RRset rrset, byte cred, Object o) {
	Name name = rrset.getName();
	short type = rrset.getType();
	short dclass = rrset.getDClass();
	int src = (o != null) ? o.hashCode() : 0;
	if (verifier != null)
		rrset.setSecurity(verifier.verify(rrset, this));
	if (secure && rrset.getSecurity() < DNSSEC.Secure)
		return;
	Element element = (Element) findExactSet(name, type, dclass);
	if (element == null || cred > element.credibility)
		addSet(name, type, dclass, new Element(rrset, cred, src));
}

/**
 * Adds a negative entry to the Cache
 * @param name The name of the negative entry
 * @param type The type of the negative entry
 * @param dclass The class of the negative entry
 * @param ttl The ttl of the negative entry
 * @param cred The credibility of the negative entry
 * @param o The source of this data
 */
public void
addNegative(Name name, short type, short dclass, int ttl, byte cred, Object o) {
	int src = (o != null) ? o.hashCode() : 0;
	Element element = (Element) findExactSet(name, type, dclass);
	if (element == null || cred > element.credibility)
		addSet(name, type, dclass, new Element(ttl, cred, src));
}

/**
 * Looks up Records in the Cache.  This follows CNAMEs and handles negatively
 * cached data.
 * @param name The name to look up
 * @param type The type to look up
 * @param dclass The class to look up
 * @param minCred The minimum acceptable credibility
 * @return A SetResponse object
 * @see SetResponse
 * @see Credibility
 */
public SetResponse
lookupRecords(Name name, short type, short dclass, byte minCred) {
	SetResponse cr = null;
	Object [] objects = findSets(name, type, dclass);

	if (objects == null)
		return new SetResponse(SetResponse.UNKNOWN);

	int nelements = 0;
	for (int i = 0; i < objects.length; i++) {
		Element element = (Element) objects[i];
		if (element.TTL0Ours()) {
			removeSet(name, type, dclass, element);
			nelements++;
		}
		else if (element.TTL0NotOurs()) {
			objects[i] = null;
		}
		else if (element.expiredTTL()) {
			removeSet(name, type, dclass, element);
			objects[i] = null;
		}
		else if (element.credibility < minCred)
			objects[i] = null;
		else
			nelements++;
	}
	if (nelements == 0)
		return new SetResponse(SetResponse.UNKNOWN);

	Element [] elements = new Element[nelements];
	for (int i = 0, j = 0; i < objects.length; i++) {
		if (objects[i] == null)
			continue;
		elements[j++] = (Element) objects[i];
	}

	for (int i = 0; i < elements.length; i++) {
		RRset rrset = elements[i].rrset;

		/* Is this a negatively cached entry? */
		if (rrset == null) {
			/*
			 * If we're looking for ANY, don't return it in
			 * case we find something better.
			 */
			if (type == Type.ANY)
				continue;
			/*
			 * If not, and we're not looking for a wildcard,
			 * try that instead.
			 */
			if (!name.isWild()) {
				cr = lookupRecords(name.wild(), type, dclass,
						   minCred);
				if (cr.isSuccessful())
					return cr;
			}
			return new SetResponse(SetResponse.NEGATIVE);
		}

		/*
		 * Found a CNAME when we weren't looking for one.  Time
		 * to recurse.
		 */
		if (type != Type.CNAME && type != Type.ANY &&
		    rrset.getType() == Type.CNAME)
		{
			CNAMERecord cname = (CNAMERecord) rrset.first();
			cr = lookupRecords(cname.getTarget(), type, dclass,
					   minCred);
			if (cr.isUnknown())
				cr.set(SetResponse.PARTIAL, cname);
			cr.addCNAME(cname);
			return cr;
		}

		/* If we found something, save it */
		if (cr == null)
			cr = new SetResponse(SetResponse.SUCCESSFUL);
		cr.addRRset(rrset);	
	}

	/*
	 * As far as I can tell, the only time cr will be null is if we
	 * queried for ANY and only saw negative responses.  So, return
	 * NEGATIVE.
	 */
	if (cr == null && type == Type.ANY)
		return new SetResponse(SetResponse.NEGATIVE);
	return cr;
}

private RRset []
findRecords(Name name, short type, short dclass, byte minCred) {
	SetResponse cr = lookupRecords(name, type, dclass, minCred);
	if (cr.isSuccessful())
		return cr.answers();
	else
		return null;
}

/**
 * Looks up credible Records in the Cache (a wrapper around lookupRecords).
 * Unlike lookupRecords, this given no indication of why failure occurred.
 * @param name The name to look up
 * @param type The type to look up
 * @param dclass The class to look up
 * @return An array of RRsets, or null
 * @see Credibility
 */
public RRset []
findRecords(Name name, short type, short dclass) {
	return findRecords(name, type, dclass, Credibility.NONAUTH_ANSWER);
}

/**
 * Looks up Records in the Cache (a wrapper around lookupRecords).  Unlike
 * lookupRecords, this given no indication of why failure occurred.
 * @param name The name to look up
 * @param type The type to look up
 * @param dclass The class to look up
 * @return An array of RRsets, or null
 * @see Credibility
 */
public RRset []
findAnyRecords(Name name, short type, short dclass) {
	return findRecords(name, type, dclass, Credibility.NONAUTH_ADDITIONAL);
}

/**
 * Adds all data from a Message into the Cache.  Each record is added with
 * the appropriate credibility, and negative answers are cached as such.
 * @param in The Message to be added
 * @see Message
 */
public void
addMessage(Message in) {
	Enumeration e;
	boolean isAuth = in.getHeader().getFlag(Flags.AA);
	Name queryName = in.getQuestion().getName();
	short queryType = in.getQuestion().getType();
	short queryClass = in.getQuestion().getDClass();
	byte cred;
	short rcode = in.getHeader().getRcode();
	int ancount = in.getHeader().getCount(Section.ANSWER);
	Cache c;

	if (secure)
		c = new Cache();
	else
		c = this;

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
		c.addRecord(r, cred, in);
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
				c.addNegative(queryName, queryType, queryClass,
					      ttl, cred, in);
			else {
				Record [] cnames;
				cnames = in.getSectionArray(Section.ANSWER);
				int last = cnames.length - 1;
				Name cname;
				cname = ((CNAMERecord)cnames[last]).getTarget();
				c.addNegative(cname, queryType, queryClass,
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
		c.addRecord(r, cred, in);
	}

	e = in.getSection(Section.ADDITIONAL);
	while (e.hasMoreElements()) {
		Record r = (Record) e.nextElement();
		if (isAuth)
			cred = Credibility.AUTH_ADDITIONAL;
		else
			cred = Credibility.NONAUTH_ADDITIONAL;
		c.addRecord(r, cred, in);
	}
	if (secure) {
		e = c.names();
		while (e.hasMoreElements()) {
			Name name = (Name) e.nextElement();
			TypeClassMap tcm = c.findName(name);
			if (tcm == null)
				continue;
			Object [] elements;
			elements = tcm.getMultiple(Type.ANY, DClass.ANY);
			if (elements == null)
				continue;
			for (int i = 0; i < elements.length; i++) {
				Element element = (Element) elements[i];
				RRset rrset = element.rrset;

				/* for now, ignore negative cache entries */
				if (rrset == null)
					continue;
				if (verifier != null)
					rrset.setSecurity(
						verifier.verify(rrset, this));
				if (rrset.getSecurity() < DNSSEC.Secure)
					continue;
				addSet(name, rrset.getType(),
				       rrset.getDClass(), element);
			}
		}
	}
}

/**
 * Flushes an RRset from the cache
 * @param name The name of the records to be flushed
 * @param type The type of the records to be flushed
 * @param dclass The class of the records to be flushed
 * @see RRset
 */
void
flushSet(Name name, short type, short dclass) {
	Element element = (Element) findExactSet(name, type, dclass);
	if (element == null || element.rrset == null)
		return;
	removeSet(name, type, dclass, element);
}

/**
 * Flushes all RRsets with a given name from the cache
 * @param name The name of the records to be flushed
 * @see RRset
 */
void
flushName(Name name) {
	removeName(name);
}

/**
 * Defines a module to be used for data verification (DNSSEC).  An
 * implementation is found in org.xbill.DNSSEC.security.DNSSECVerifier,
 * which requires Java 2 or above and the Java Cryptography Extensions.
 */
public void
setVerifier(Verifier v) {
        verifier = v;
}

/**
 * Mandates that all data stored in this Cache must be verified and proven
 * to be secure, using a verifier (as defined in setVerifier).
 */
public void
setSecurePolicy() {
        secure = true;
}

}

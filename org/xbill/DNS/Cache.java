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

private static abstract class Element {
	byte credibility;
	int expire;

	protected void
	setValues(byte credibility, long ttl) {
		this.credibility = credibility;
		this.expire = (int)((System.currentTimeMillis() / 1000) + ttl);
		if (this.expire  < 0)
			this.expire = Integer.MAX_VALUE;
	}

	public final boolean
	expired() {
		int now = (int)(System.currentTimeMillis() / 1000);
		return (now > expire);
	}

	public abstract short getType();
}

private static class PositiveElement extends Element {
	RRset rrset;
	int srcid;

	public
	PositiveElement(RRset r, byte cred, int src) {
		rrset = r;
		srcid = src;
		setValues(cred, r.getTTL());
	}

	public short
	getType() {
		return rrset.getType();
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

private class NegativeElement extends Element {
	short type;
	Name name;

	public
	NegativeElement(Name name, long ttl, byte cred, short type) {
		this.name = name;
		this.type = type;
		setValues(cred, ttl);
	}

	public short
	getType() {
		return type;
	}

	public String
	toString() {
		StringBuffer sb = new StringBuffer();
		if (type == 0)
			sb.append("NXDOMAIN " + name);
		else
			sb.append("NXRRSET " + name + " " + Type.string(type));
		sb.append(" cl = ");
		sb.append(credibility);
		return sb.toString();
	}
}

private class CacheCleaner extends Thread {
	public boolean done;

	public
	CacheCleaner() {
		setDaemon(true);
		setName("CacheCleaner");
		start();
	}

	public void
	clean() {
		Iterator it = names();
		while (it.hasNext()) {
			Name name = (Name) it.next();
			TypeMap tm = findName(name);
			if (tm == null)
				continue;
			Object [] elements;
			elements = tm.getAll();
			if (elements == null)
				continue;
			for (int i = 0; i < elements.length; i++) {
				Element element = (Element) elements[i];
				if (element.expired())
					removeSet(name, element.getType(),
						  element);
			}
		}
	}

	public void
	run() {
		while (true) {
			long now = System.currentTimeMillis();
			long next = now + cleanInterval * 60 * 1000;
			while (now < next) {
				try {
					Thread.sleep(next - now);
				}
				catch (InterruptedException e) {
					if (done)
						return;
				}
				now = System.currentTimeMillis();
			}
			clean();
		}
	}
}

private Verifier verifier;
private boolean secure;
private int maxncache = -1;
private long cleanInterval = 30;
private CacheCleaner cleaner;
private short dclass;

/**
 * Creates an empty Cache
 *
 * @param dclass The dns class of this cache
 * @see DClass
 */
public
Cache(short dclass) {
	super(true);
	cleaner = new CacheCleaner();
	this.dclass = dclass;
}

/**
 * Creates an empty Cache for class IN.
 * @see DClass
 */
public
Cache() {
	this(DClass.IN);
}

/** Empties the Cache. */
public void
clearCache() {
	clear();
}

/**
 * Creates a Cache which initially contains all records in the specified file.
 */
public
Cache(String file) throws IOException {
	super(true);
	cleaner = new CacheCleaner();
	Master m = new Master(file);
	Record record;
	while ((record = m.nextRecord()) != null)
		addRecord(record, Credibility.HINT, m);
}

/**
 * Adds a record to the Cache.
 * @param r The record to be added
 * @param cred The credibility of the record
 * @param o The source of the record (this could be a Message, for example)
 * @see Record
 */
public void
addRecord(Record r, byte cred, Object o) {
	Name name = r.getName();
	short type = r.getRRsetType();
	if (!Type.isRR(type))
		return;
	boolean addrrset = false;
	Element element = (Element) findExactSet(name, type);
	if (element == null || cred > element.credibility)
		addrrset = true;
	else if (cred == element.credibility) {
		if (element instanceof PositiveElement) {
			PositiveElement pe = (PositiveElement) element;
			int src = (o != null) ? o.hashCode() : 0;
			if (pe.srcid != src)
				addrrset = true;
			else
				pe.rrset.addRR(r);
		}
	}
	if (addrrset) {
		RRset rrset = new RRset();
		rrset.addRR(r);
		addRRset(rrset, cred, o);
	}
}

/**
 * Adds an RRset to the Cache.
 * @param r The RRset to be added
 * @param cred The credibility of these records
 * @param o The source of this RRset (this could be a Message, for example)
 * @see RRset
 */
public void
addRRset(RRset rrset, byte cred, Object o) {
	Name name = rrset.getName();
	short type = rrset.getType();
	int src = (o != null) ? o.hashCode() : 0;
	if (verifier != null)
		rrset.setSecurity(verifier.verify(rrset, this));
	if (secure && rrset.getSecurity() < DNSSEC.Secure)
		return;
	Element element = (Element) findExactSet(name, type);
	if (element == null || cred > element.credibility)
		addSet(name, type, new PositiveElement(rrset, cred, src));
}

/**
 * Adds a negative entry to the Cache.
 * @param name The name of the negative entry
 * @param type The type of the negative entry
 * @param ttl The ttl of the negative entry
 * @param cred The credibility of the negative entry
 */
public void
addNegative(Name name, short type, long ttl, byte cred) {
	Element element = (Element) findExactSet(name, type);
	if (element == null || cred > element.credibility)
		addSet(name, type, new NegativeElement(name, ttl, cred, type));
}

private void
logLookup(Name name, short type, String msg) {
	System.err.println("lookupRecords(" + name + " " +
			   Type.string(type) + "): " + msg);
}

/**
 * Looks up Records in the Cache.  This follows CNAMEs and handles negatively
 * cached data.
 * @param name The name to look up
 * @param type The type to look up
 * @param minCred The minimum acceptable credibility
 * @return A SetResponse object
 * @see SetResponse
 * @see Credibility
 */
public SetResponse
lookupRecords(Name name, short type, byte minCred) {
	SetResponse cr = null;
	boolean verbose = Options.check("verbosecache");
	Object o = findSets(name, type);

	if (verbose)
		logLookup(name, type, "Starting");

 	if (o == null || o instanceof TypeMap) {
		/*
		 * The name exists, but the type was not found.  Or, the
		 * name does not exist and no parent does either.  Punt.
		 */
		if (verbose)
			logLookup(name, type, "no information found");
		return SetResponse.ofType(SetResponse.UNKNOWN);
	}

	Object [] objects;
	if (o instanceof Element)
		objects = new Object[] {o};
	else
		objects = (Object[]) o;
		
	int nelements = 0;
	for (int i = 0; i < objects.length; i++) {
		Element element = (Element) objects[i];
		if (element.expired()) {
			if (verbose) {
				logLookup(name, type, element.toString());
				logLookup(name, type, "expired: ignoring");
			}
			removeSet(name, type, element);
			objects[i] = null;
		}
		else if (element.credibility < minCred) {
			if (verbose) {
				logLookup(name, type, element.toString());
				logLookup(name, type, "not credible: ignoring");
			}
			objects[i] = null;
		}
		else {
			nelements++;
		}
	}
	if (nelements == 0) {
		/* We have data, but can't use it.  Punt. */
		if (verbose)
			logLookup(name, type, "no useful data found");
		return SetResponse.ofType(SetResponse.UNKNOWN);
	}

	/*
	 * We have something at the name.  It could be the answer,
	 * a CNAME, DNAME, or NS, or a negative cache entry.
	 * 
	 * Ignore wildcards, since it's pretty unlikely that any will be
	 * cached.  The occasional extra query is easily balanced by the
	 * reduced number of lookups.
	 */

	for (int i = 0; i < objects.length; i++) {
		if (objects[i] == null)
			continue;
		Element element = (Element) objects[i];
		if (verbose)
			logLookup(name, type, element.toString());
		RRset rrset = null;
		if (element instanceof PositiveElement)
			rrset = ((PositiveElement) element).rrset;

		/* Is this a negatively cached entry? */
		if (rrset == null) {
			/*
			 * If this is an NXDOMAIN entry, return NXDOMAIN.
			 */
			if (element.getType() == 0) {
				if (verbose)
					logLookup(name, type, "NXDOMAIN");
				return SetResponse.ofType(SetResponse.NXDOMAIN);
			}

			/*
			 * If we're not looking for type ANY, return NXRRSET.
			 * Otherwise ignore this.
			 */
			if (type != Type.ANY) {
				if (verbose)
					logLookup(name, type, "NXRRSET");
				return SetResponse.ofType(SetResponse.NXRRSET);
			} else {
				if (verbose)
					logLookup(name, type,
						  "ANY query; " +
						  "ignoring NXRRSET");
				continue;
			}
		}

		short rtype = rrset.getType();
		Name rname = rrset.getName();
		if (name.equals(rname)) {
			if (type != Type.CNAME && type != Type.ANY &&
			    rtype == Type.CNAME)
			{
				if (verbose)
					logLookup(name, type, "cname");
				return new SetResponse(SetResponse.CNAME,
						       rrset);
			} else if (type != Type.NS && type != Type.ANY &&
				   rtype == Type.NS)
			{
				if (verbose)
					logLookup(name, type,
						  "exact delegation");
				return new SetResponse(SetResponse.DELEGATION,
						       rrset);
			} else {
				if (verbose)
					logLookup(name, type, "exact match");
				if (cr == null)
					cr = new SetResponse
						(SetResponse.SUCCESSFUL);
				cr.addRRset(rrset);
			}
		}
		else if (name.subdomain(rname)) {
			if (rtype == Type.DNAME) {
				if (verbose)
					logLookup(name, type, "dname");
				return new SetResponse(SetResponse.DNAME,
						       rrset);
			} else if (rtype == Type.NS) {
				if (verbose)
					logLookup(name, type,
						  "parent delegation");
				return new SetResponse(SetResponse.DELEGATION,
						       rrset);
			} else {
				if (verbose)
					logLookup(name, type,
						  "ignoring rrset (" +
						  rname + " " +
						  Type.string(rtype) + ")");
			}
		} else {
			if (verbose)
				logLookup(name, type,
					  "ignoring rrset (" + rname + " " +
					  Type.string(rtype) + ")");
		}
	}

	/*
	 * As far as I can tell, the only legitimate time cr will be null is
	 * if we queried for ANY and only saw negative responses, but not an
	 * NXDOMAIN.  Return UNKNOWN.
	 */
	if (cr == null && type == Type.ANY)
		return SetResponse.ofType(SetResponse.UNKNOWN);
	else if (cr == null)
		throw new IllegalStateException("looking up (" + name + " " +
						Type.string(type) + "): " +
						"cr == null.");
	return cr;
}

private RRset []
findRecords(Name name, short type, byte minCred) {
	SetResponse cr = lookupRecords(name, type, minCred);
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
 * @return An array of RRsets, or null
 * @see Credibility
 */
public RRset []
findRecords(Name name, short type) {
	return findRecords(name, type, Credibility.NONAUTH_ANSWER);
}

/**
 * Looks up Records in the Cache (a wrapper around lookupRecords).  Unlike
 * lookupRecords, this given no indication of why failure occurred.
 * @param name The name to look up
 * @param type The type to look up
 * @return An array of RRsets, or null
 * @see Credibility
 */
public RRset []
findAnyRecords(Name name, short type) {
	return findRecords(name, type, Credibility.NONAUTH_ADDITIONAL);
}

private void
verifyRecords(Cache tcache) {
	Iterator it;

	it = tcache.names();
	while (it.hasNext()) {
		Name name = (Name) it.next();
		TypeMap tm = tcache.findName(name);
		if (tm == null)
			continue;
		Object [] elements;
		elements = tm.getAll();
		if (elements == null)
			continue;
		for (int i = 0; i < elements.length; i++) {
			Element element = (Element) elements[i];
			if (element instanceof PositiveElement)
				continue;
			RRset rrset = ((PositiveElement) element).rrset;

			/* for now, ignore negative cache entries */
			if (rrset == null)
				continue;
			if (verifier != null)
				rrset.setSecurity(verifier.verify(rrset, this));
			if (rrset.getSecurity() < DNSSEC.Secure)
				continue;
			addSet(name, rrset.getType(), element);
		}
	}
}

private final byte
getCred(Name recordName, Name queryName, short section, boolean isAuth) {
	byte cred;

	if (section == Section.ANSWER) {
		if (isAuth && recordName.equals(queryName))
			cred = Credibility.AUTH_ANSWER;
		else if (isAuth)
			cred = Credibility.AUTH_NONAUTH_ANSWER;
		else
			cred = Credibility.NONAUTH_ANSWER;
	} else if (section == Section.AUTHORITY) {
		if (isAuth)
			cred = Credibility.AUTH_AUTHORITY;
		else
			cred = Credibility.NONAUTH_AUTHORITY;
	} else if (section == Section.ADDITIONAL) {
		if (isAuth)
			cred = Credibility.AUTH_ADDITIONAL;
		else
			cred = Credibility.NONAUTH_ADDITIONAL;
	} else
		throw new IllegalArgumentException("getCred: invalid section");
	return cred;
}

/**
 * Adds all data from a Message into the Cache.  Each record is added with
 * the appropriate credibility, and negative answers are cached as such.
 * @param in The Message to be added
 * @see Message
 */
public void
addMessage(Message in) {
	boolean isAuth = in.getHeader().getFlag(Flags.AA);
	Name queryName = in.getQuestion().getName();
	Name lookupName = queryName;
	short queryType = in.getQuestion().getType();
	short queryClass = in.getQuestion().getDClass();
	byte cred;
	short rcode = in.getHeader().getRcode();
	boolean haveAnswer = false;
	Record [] answers, auth, addl;

	if (secure) {
		Cache c = new Cache(dclass);
		c.addMessage(in);
		verifyRecords(c);
		return;
	}

	if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN)
		return;

	answers = in.getSectionArray(Section.ANSWER);
	while (!haveAnswer || queryType == Type.ANY) {
		boolean restart = false;
		for (int i = 0; i < answers.length; i++) {
			short type = answers[i].getType();
			short rrtype = answers[i].getRRsetType();
			Name name = answers[i].getName();
			cred = getCred(name, queryName, Section.ANSWER, isAuth);
			if (type == Type.CNAME && name.equals(lookupName)) {
				addRecord(answers[i], cred, in);
				CNAMERecord cname = (CNAMERecord) answers[i];
				lookupName = cname.getTarget();
				restart = true;
			} else if (rrtype == Type.CNAME &&
				   name.equals(lookupName))
			{
				addRecord(answers[i], cred, in);
			} else if (type == Type.DNAME &&
				   lookupName.subdomain(name))
			{
				addRecord(answers[i], cred, in);
				DNAMERecord dname = (DNAMERecord) answers[i];
				try {
					lookupName =
						lookupName.fromDNAME(dname);
				}
				catch (NameTooLongException e) {
					break;
				}
				restart = true;
			} else if (rrtype == Type.DNAME &&
				   lookupName.subdomain(name))
			{
				addRecord(answers[i], cred, in);
			} else if ((rrtype == queryType ||
				  queryType == Type.ANY) &&
				 name.equals(lookupName))
			{
				addRecord(answers[i], cred, in);
				haveAnswer = true;
			}
		}
		if (!restart)
			break;
	}

	auth = in.getSectionArray(Section.AUTHORITY);

	if (!haveAnswer) {
		/* This is a negative response */
		SOARecord soa = null;
		for (int i = 0; i < auth.length; i++) {
			if (auth[i].getType() == Type.SOA &&
			    lookupName.subdomain(auth[i].getName()))
			{
				soa = (SOARecord) auth[i];
				break;
			}
		}
		if (soa != null) {
			/* This is a cacheable negative response. */
			long ttl = (long)soa.getMinimum() & 0xFFFFFFFFL;
			if (maxncache >= 0)
				ttl = Math.min(ttl, maxncache);
			cred = getCred(soa.getName(), queryName,
				       Section.AUTHORITY, isAuth);
			if (rcode == Rcode.NXDOMAIN)
				addNegative(lookupName, (short)0, ttl, cred);
			else
				addNegative(lookupName, queryType, ttl, cred);
		}
	}

	for (int i = 0; i < auth.length; i++) {
		short type = auth[i].getRRsetType();
		Name name = auth[i].getName();
		if ((type == Type.NS || type == Type.SOA) &&
		    lookupName.subdomain(name))
		{
			cred = getCred(name, queryName, Section.AUTHORITY,
				       isAuth);
			addRecord(auth[i], cred, in);
		}
		/* NXT records are not cached yet. */
	}

	addl = in.getSectionArray(Section.ADDITIONAL);
	for (int i = 0; i < addl.length; i++) {
		short type = addl[i].getRRsetType();
		if (type != Type.A && type != Type.AAAA && type != Type.A6)
			continue;
		/* XXX check the name */
		Name name = addl[i].getName();
		cred = getCred(name, queryName, Section.ADDITIONAL, isAuth);
		addRecord(addl[i], cred, in);
	}
}

/**
 * Flushes an RRset from the cache
 * @param name The name of the records to be flushed
 * @param type The type of the records to be flushed
 * @see RRset
 */
public void
flushSet(Name name, short type) {
	Element element = (Element) findExactSet(name, type);
	if (element == null)
		return;
	removeSet(name, type, element);
}

/**
 * Flushes all RRsets with a given name from the cache
 * @param name The name of the records to be flushed
 * @see RRset
 */
public void
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

/**
 * Sets the maximum length of time that a negative response will be stored
 * in this Cache.  A negative value disables this feature (that is, sets
 * no limit).
 */
public void
setMaxNCache(int seconds) {
	maxncache = seconds;
}

/**
 * Sets the interval (in minutes) that all expired records will be expunged
 * the cache.  The default is 30 minutes.  0 or a negative value disables this
 * feature.
 */
public void
setCleanInterval(int minutes) {
	cleanInterval = minutes;
	if (cleaner != null) {
		cleaner.done = true;
		cleaner.interrupt();
	}
	if (cleanInterval > 0)
		cleaner = new CacheCleaner();
}

}

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

private static abstract class Element implements TypedObject {
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
		return (now >= expire);
	}

	public abstract short getType();
}

private static class PositiveElement extends Element {
	RRset rrset;

	public
	PositiveElement(RRset r, byte cred) {
		rrset = r;
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
	SOARecord soa;

	public
	NegativeElement(Name name, short type, SOARecord soa, byte cred) {
		this.name = name;
		this.type = type;
		this.soa = soa;
		long cttl = 0;
		if (soa != null) {
			cttl = soa.getMinimum() & 0xFFFFFFFFL;
			if (maxncache >= 0)
				cttl = Math.min(cttl, maxncache);
		}
		setValues(cred, cttl);
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

	public boolean
	clean() {
		Iterator it = names();
		while (it.hasNext()) {
			Name name;
			try {
				name = (Name) it.next();
			} catch (ConcurrentModificationException e) {
				return false;
			}
			Object [] elements = findExactSets(name);
			for (int i = 0; i < elements.length; i++) {
				Element element = (Element) elements[i];
				if (element.expired())
					removeSet(name, element.getType(),
						  element);
			}
		}
		return true;
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
			for (int i = 0; i < 4; i++)
				if (clean())
					break;
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
	if (element == null || cred > element.credibility) {
		RRset rrset = new RRset();
		rrset.addRR(r);
		addRRset(rrset, cred);
	}
	else if (cred == element.credibility) {
		if (element instanceof PositiveElement) {
			PositiveElement pe = (PositiveElement) element;
			pe.rrset.addRR(r);
		}
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
addRRset(RRset rrset, byte cred) {
	if (rrset.getTTL() == 0)
		return;
	Name name = rrset.getName();
	short type = rrset.getType();
	if (verifier != null)
		rrset.setSecurity(verifier.verify(rrset, this));
	if (secure && rrset.getSecurity() < DNSSEC.Secure)
		return;
	Element element = (Element) findExactSet(name, type);
	if (rrset.getTTL() == 0) {
		if (element != null && cred >= element.credibility)
			removeSet(name, type, element);
	} else {
		if (element == null || cred >= element.credibility)
			addSet(name, type, new PositiveElement(rrset, cred));
	}
}

/**
 * Adds a negative entry to the Cache.
 * @param name The name of the negative entry
 * @param type The type of the negative entry
 * @param soa The SOA record to add to the negative cache entry, or null.
 * The negative cache ttl is derived from the SOA.
 * @param cred The credibility of the negative entry
 */
public void
addNegative(Name name, short type, SOARecord soa, byte cred) {
	if (verifier != null && secure)
		return;
	Element element = (Element) findExactSet(name, type);
	if (soa == null || soa.getTTL() == 0) {
		if (element != null && cred >= element.credibility)
			removeSet(name, type, element);
	}
	if (element == null || cred >= element.credibility)
		addSet(name, type, new NegativeElement(name, type, soa, cred));
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
	Object o = lookup(name, type);

	if (verbose)
		logLookup(name, type, "Starting");

 	if (o == null || o == NXRRSET) {
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
	return findRecords(name, type, Credibility.NORMAL);
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
	return findRecords(name, type, Credibility.GLUE);
}

private void
verifyRecords(Cache tcache) {
	Iterator it;

	it = tcache.names();
	while (it.hasNext()) {
		Name name = (Name) it.next();
		Object [] elements = findExactSets(name);
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
getCred(short section, boolean isAuth) {
	if (section == Section.ANSWER) {
		if (isAuth)
			return Credibility.AUTH_ANSWER;
		else
			return Credibility.NONAUTH_ANSWER;
	} else if (section == Section.AUTHORITY) {
		if (isAuth)
			return Credibility.AUTH_AUTHORITY;
		else
			return Credibility.NONAUTH_AUTHORITY;
	} else if (section == Section.ADDITIONAL) {
		return Credibility.ADDITIONAL;
	} else
		throw new IllegalArgumentException("getCred: invalid section");
}

private static void
markAdditional(RRset rrset, Set names) {
	Record first = rrset.first();
	if (first.getAdditionalName() == null)
		return;

	Iterator it = rrset.rrs();
	while (it.hasNext()) {
		Record r = (Record) it.next();
		Name name = r.getAdditionalName();
		if (name != null)
			names.add(name);
	}
}

/**
 * Adds all data from a Message into the Cache.  Each record is added with
 * the appropriate credibility, and negative answers are cached as such.
 * @param in The Message to be added
 * @return A SetResponse that reflects what would be returned from a cache
 * lookup, or null if nothing useful could be cached from the message.
 * @see Message
 */
public SetResponse
addMessage(Message in) {
	boolean isAuth = in.getHeader().getFlag(Flags.AA);
	Record question = in.getQuestion();
	Name qname;
	Name curname;
	short qtype;
	short qclass;
	byte cred;
	short rcode = in.getHeader().getRcode();
	boolean haveAnswer = false;
	boolean completed = false;
	boolean restart = false;
	RRset [] answers, auth, addl;
	SetResponse response = null;
	boolean verbose = Options.check("verbosecache");
	HashSet additionalNames;

	if ((rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) ||
	    question == null)
		return null;

	qname = question.getName();
	qtype = question.getType();
	qclass = question.getDClass();

	curname = qname;

	additionalNames = new HashSet();

	answers = in.getSectionRRsets(Section.ANSWER);
	for (int i = 0; i < answers.length; i++) {
		if (answers[i].getDClass() != qclass)
			continue;
		short type = answers[i].getType();
		Name name = answers[i].getName();
		cred = getCred(Section.ANSWER, isAuth);
		if (type == Type.CNAME && name.equals(curname)) {
			CNAMERecord cname;
			addRRset(answers[i], cred);
			if (curname == qname)
				response = new SetResponse(SetResponse.CNAME,
							   answers[i]);
			cname = (CNAMERecord) answers[i].first();
			curname = cname.getTarget();
			restart = true;
			haveAnswer = true;
		} else if (type == Type.DNAME && curname.subdomain(name)) {
			DNAMERecord dname;
			addRRset(answers[i], cred);
			if (curname == qname)
				response = new SetResponse(SetResponse.DNAME,
							   answers[i]);
			dname = (DNAMERecord) answers[i].first();
			try {
				curname = curname.fromDNAME(dname);
			}
			catch (NameTooLongException e) {
				break;
			}
			restart = true;
			haveAnswer = true;
		} else if ((type == qtype || qtype == Type.ANY) &&
			   name.equals(curname))
		{
			addRRset(answers[i], cred);
			completed = true;
			haveAnswer = true;
			if (curname == qname) {
				if (response == null)
					response = new SetResponse(
							SetResponse.SUCCESSFUL);
				response.addRRset(answers[i]);
			}
			markAdditional(answers[i], additionalNames);
		}
		if (restart) {
			restart = false;
			i = -1;
		}
	}

	auth = in.getSectionRRsets(Section.AUTHORITY);
	RRset soa = null, ns = null;
	for (int i = 0; i < auth.length; i++) {
		if (auth[i].getType() == Type.SOA &&
		    curname.subdomain(auth[i].getName()))
			soa = auth[i];
		else if (auth[i].getType() == Type.NS &&
			 curname.subdomain(auth[i].getName()))
			ns = auth[i];
	}
	if (!completed) {
		/* This is a negative response or a referral. */
		short cachetype = (rcode == Rcode.NXDOMAIN) ? (short)0 : qtype;
		if (soa != null || ns == null) {
			/* Negative response */
			cred = getCred(Section.AUTHORITY, isAuth);
			SOARecord soarec = null;
			if (soa != null)
				soarec = (SOARecord) soa.first();
			addNegative(curname, cachetype, soarec, cred);
			if (response == null) {
				byte responseType;
				if (rcode == Rcode.NXDOMAIN)
					responseType = SetResponse.NXDOMAIN;
				else
					responseType = SetResponse.NXRRSET;
				response = SetResponse.ofType(responseType);
			}
			/* NXT records are not cached yet. */
		} else if (ns != null) {
			/* Referral response */
			cred = getCred(Section.AUTHORITY, isAuth);
			addRRset(ns, cred);
			markAdditional(ns, additionalNames);
			if (response == null)
				response = new SetResponse(
							SetResponse.DELEGATION,
							ns);
		}
	} else if (rcode == Rcode.NOERROR && ns != null) {
		/* Cache the NS set from a positive response. */
		cred = getCred(Section.AUTHORITY, isAuth);
		addRRset(ns, cred);
		markAdditional(ns, additionalNames);
	}

	addl = in.getSectionRRsets(Section.ADDITIONAL);
	for (int i = 0; i < addl.length; i++) {
		short type = addl[i].getType();
		if (type != Type.A && type != Type.AAAA && type != Type.A6)
			continue;
		Name name = addl[i].getName();
		if (!additionalNames.contains(name))
			continue;
		cred = getCred(Section.ADDITIONAL, isAuth);
		addRRset(addl[i], cred);
	}
	if (verbose)
		System.out.println("addMessage: " + response);
	return (response);
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

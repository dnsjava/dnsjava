// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import java.lang.ref.*;

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

public class Cache {

private abstract static class Element implements TypedObject {
	int credibility;
	int expire;

	protected void
	setValues(int credibility, long ttl) {
		this.credibility = credibility;
		this.expire = (int)((System.currentTimeMillis() / 1000) + ttl);
		if (this.expire < 0 || this.expire > Integer.MAX_VALUE)
			this.expire = Integer.MAX_VALUE;
	}

	public final boolean
	expired() {
		int now = (int)(System.currentTimeMillis() / 1000);
		return (now >= expire);
	}

	public abstract int getType();
}

private static class PositiveElement extends Element {
	RRset rrset;

	public
	PositiveElement(RRset r, int cred, long maxttl) {
		rrset = r;
		long ttl = r.getTTL();
		if (maxttl >= 0 && maxttl < ttl)
			ttl = maxttl;
		setValues(cred, ttl);
	}

	public int
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

private static class NegativeElement extends Element {
	int type;
	Name name;
	SOARecord soa;

	public
	NegativeElement(Name name, int type, SOARecord soa, int cred,
			long maxttl)
	{
		this.name = name;
		this.type = type;
		this.soa = soa;
		long cttl = 0;
		if (soa != null) {
			cttl = soa.getMinimum();
			if (maxttl >= 0 && maxttl < cttl)
				cttl = maxttl;
		}
		setValues(cred, cttl);
	}

	public int
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

private static class CacheCleaner extends Thread {
	private Reference cacheref;
	private long interval;

	public
	CacheCleaner(Cache cache, int cleanInterval) {
		this.cacheref = new WeakReference(cache);
		this.interval = (long)cleanInterval * 60 * 1000;
		setDaemon(true);
		setName("org.xbill.DNS.Cache.CacheCleaner");
		start();
	}

	private boolean
	clean(Cache cache) {
		Iterator it = cache.data.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry entry;
			try {
				entry = (Map.Entry) it.next();
			} catch (ConcurrentModificationException e) {
				return false;
			}
			Name name = (Name) entry.getKey();
			Element [] elements =
				cache.allElements(entry.getValue());
			for (int i = 0; i < elements.length; i++) {
				Element element = elements[i];
				if (element.expired())
					cache.removeElement(name,
							    element.getType());
			}
		}
		return true;
	}

	public void
	run() {
		while (true) {
			long now = System.currentTimeMillis();
			long next = now + interval;
			while (now < next) {
				try {
					Thread.sleep(next - now);
				}
				catch (InterruptedException e) {
					return;
				}
				now = System.currentTimeMillis();
			}
			Cache cache = (Cache) cacheref.get();
			if (cache == null) {
				return;
			}
			for (int i = 0; i < 4; i++)
				if (clean(cache))
					break;
		}
	}
}

private static final int defaultCleanInterval = 30;

private Map data;
private int maxncache = -1;
private int maxcache = -1;
private CacheCleaner cleaner;
private int dclass;

/**
 * Creates an empty Cache
 *
 * @param dclass The dns class of this cache
 * @param cleanInterval The interval between cache cleanings, in minutes.
 * @see #setCleanInterval(int)
 */
public
Cache(int dclass, int cleanInterval) {
	data = new HashMap();
	this.dclass = dclass;
	setCleanInterval(cleanInterval);
}

/**
 * Creates an empty Cache
 *
 * @param dclass The dns class of this cache
 * @see DClass
 */
public
Cache(int dclass) {
	this(dclass, defaultCleanInterval);
}

/**
 * Creates an empty Cache for class IN.
 * @see DClass
 */
public
Cache() {
	this(DClass.IN, defaultCleanInterval);
}

/**
 * Creates a Cache which initially contains all records in the specified file.
 */
public
Cache(String file) throws IOException {
	data = new HashMap();
	cleaner = new CacheCleaner(this, defaultCleanInterval);
	Master m = new Master(file);
	Record record;
	while ((record = m.nextRecord()) != null)
		addRecord(record, Credibility.HINT, m);
}

private synchronized Object
exactName(Name name) {
	return data.get(name);
}

private synchronized void
removeName(Name name) {
	data.remove(name);
}

private synchronized Element []
allElements(Object types) {
	if (types instanceof List) {
		List typelist = (List) types;
		int size = typelist.size();
		return (Element []) typelist.toArray(new Element[size]);
	} else {
		Element set = (Element) types;
		return new Element[] {set};
	}
}

private synchronized Element
oneElement(Object types, int type) {
	if (type == Type.ANY)
		throw new IllegalArgumentException("oneElement(ANY)");
	if (types instanceof List) {
		List list = (List) types;
		for (int i = 0; i < list.size(); i++) {
			Element set = (Element) list.get(i);
			if (set.getType() == type)
				return set;
		}
	} else {
		Element set = (Element) types;
		if (set.getType() == type)
			return set;
	}
	return null;
}

private synchronized Element
oneElementWithCheck(Name name, Object types, int type, int minCred) {
	Element element = oneElement(types, type);
	if (element == null)
		return null;
	if (element.expired()) {
		removeElement(name, type);
		return null;
	}
	if (element.credibility < minCred)
		return null;
	return element;
}

private synchronized Element
findElement(Name name, int type) {
	Object types = exactName(name);
	if (types == null)
		return null;
	return oneElement(types, type);
}

private synchronized void
addElement(Name name, Element element) {
	Object types = data.get(name);
	if (types == null) {
		data.put(name, element);
		return;
	}
	int type = element.getType();
	if (types instanceof List) {
		List list = (List) types;
		for (int i = 0; i < list.size(); i++) {
			Element elt = (Element) list.get(i);
			if (elt.getType() == type) {
				list.set(i, element);
				return;
			}
		}
		list.add(element);
	} else {
		Element elt = (Element) types;
		if (elt.getType() == type)
			data.put(name, element);
		else {
			LinkedList list = new LinkedList();
			list.add(elt);
			list.add(element);
			data.put(name, list);
		}
	}
}

private synchronized void
removeElement(Name name, int type) {
	Object types = data.get(name);
	if (types == null) {
		return;
	}
	if (types instanceof List) {
		List list = (List) types;
		for (int i = 0; i < list.size(); i++) {
			Element elt = (Element) list.get(i);
			if (elt.getType() == type) {
				list.remove(i);
				if (list.size() == 0)
					data.remove(name);
				return;
			}
		}
	} else {
		Element elt = (Element) types;
		if (elt.getType() != type)
			return;
		data.remove(name);
	}
}

/** Empties the Cache. */
public void
clearCache() {
	synchronized (this) {
		data.clear();
	}
}

/**
 * Adds a record to the Cache.
 * @param r The record to be added
 * @param cred The credibility of the record
 * @param o The source of the record (this could be a Message, for example)
 * @see Record
 */
public void
addRecord(Record r, int cred, Object o) {
	Name name = r.getName();
	int type = r.getRRsetType();
	if (!Type.isRR(type))
		return;
	Element element = findElement(name, type);
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
 * @param rrset The RRset to be added
 * @param cred The credibility of these records
 * @see RRset
 */
public void
addRRset(RRset rrset, int cred) {
	long ttl = rrset.getTTL();
	Name name = rrset.getName();
	int type = rrset.getType();
	Element element = findElement(name, type);
	if (ttl == 0) {
		if (element != null && cred >= element.credibility)
			removeElement(name, type);
	} else {
		if (element == null || cred >= element.credibility)
			addElement(name,
				   new PositiveElement(rrset, cred, maxcache));
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
addNegative(Name name, int type, SOARecord soa, int cred) {
	Element element = findElement(name, type);
	if (soa == null || soa.getTTL() == 0) {
		if (element != null && cred >= element.credibility)
			removeElement(name, type);
	}
	if (element == null || cred >= element.credibility)
		addElement(name, new NegativeElement(name, type, soa, cred,
						     maxncache));
}

private void
logLookup(Name name, int type, String msg) {
	System.err.println("lookupRecords(" + name + " " +
			   Type.string(type) + "): " + msg);
}

/**
 * Finds all matching sets or something that causes the lookup to stop.
 */
protected synchronized SetResponse
lookup(Name name, int type, int minCred) {
	int labels;
	int tlabels;
	Element element;
	PositiveElement pe;
	Name tname;
	Object types;
	SetResponse sr;

	labels = name.labels();

	for (tlabels = labels; tlabels >= 1; tlabels--) {
		boolean isRoot = (tlabels == 1);
		boolean isExact = (tlabels == labels);

		if (isRoot)
			tname = Name.root;
		else if (isExact)
			tname = name;
		else
			tname = new Name(name, labels - tlabels);

		types = data.get(tname);
		if (types == null)
			continue;

		/* If this is an ANY lookup, return everything. */
		if (isExact && type == Type.ANY) {
			sr = new SetResponse(SetResponse.SUCCESSFUL);
			Element [] elements = allElements(types);
			int added = 0;
			for (int i = 0; i < elements.length; i++) {
				element = elements[i];
				if (element.expired()) {
					removeElement(tname, element.getType());
					continue;
				}
				if (element instanceof NegativeElement)
					continue;
				if (element.credibility < minCred)
					continue;
				pe = (PositiveElement) element;
				sr.addRRset(pe.rrset);
				added++;
			}
			/* There were positive entries */
			if (added > 0)
				return sr;
		}

		/* Look for an NS */
		element = oneElementWithCheck(tname, types, Type.NS, minCred);
		if (element != null && element instanceof PositiveElement) {
			pe = (PositiveElement) element;
			return new SetResponse(SetResponse.DELEGATION,
					       pe.rrset);
		}

		/*
		 * If this is the name, look for the actual type or a CNAME.
		 * Otherwise, look for a DNAME.
		 */
		if (isExact) {
			element = oneElementWithCheck(tname, types, type,
						      minCred);
			if (element != null &&
			    element instanceof PositiveElement)
			{
				pe = (PositiveElement) element;
				sr = new SetResponse(SetResponse.SUCCESSFUL);
				sr.addRRset(pe.rrset);
				return sr;
			} else if (element != null) {
				sr = new SetResponse(SetResponse.NXRRSET);
				return sr;
			}

			element = oneElementWithCheck(tname, types, Type.CNAME,
						      minCred);
			if (element != null &&
			    element instanceof PositiveElement)
			{
				pe = (PositiveElement) element;
				return new SetResponse(SetResponse.CNAME,
						       pe.rrset);
			}
		} else {
			element = oneElementWithCheck(tname, types, Type.DNAME,
						      minCred);
			if (element != null &&
			    element instanceof PositiveElement)
			{
				pe = (PositiveElement) element;
				return new SetResponse(SetResponse.DNAME,
						       pe.rrset);
			}
		}

		/* Check for the special NXDOMAIN element. */
		if (isExact) {
			element = oneElementWithCheck(tname, types, 0, minCred);
			if (element != null)
				return SetResponse.ofType(SetResponse.NXDOMAIN);
		}

	}
	return SetResponse.ofType(SetResponse.UNKNOWN);
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
lookupRecords(Name name, int type, int minCred) {
	return lookup(name, type, minCred);
}

private RRset []
findRecords(Name name, int type, int minCred) {
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
findRecords(Name name, int type) {
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
findAnyRecords(Name name, int type) {
	return findRecords(name, type, Credibility.GLUE);
}

private final int
getCred(int section, boolean isAuth) {
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
	int qtype;
	int qclass;
	int cred;
	int rcode = in.getHeader().getRcode();
	boolean haveAnswer = false;
	boolean completed = false;
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
		int type = answers[i].getType();
		Name name = answers[i].getName();
		cred = getCred(Section.ANSWER, isAuth);
		if ((type == qtype || qtype == Type.ANY) &&
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
		} else if (type == Type.CNAME && name.equals(curname)) {
			CNAMERecord cname;
			addRRset(answers[i], cred);
			if (curname == qname)
				response = new SetResponse(SetResponse.CNAME,
							   answers[i]);
			cname = (CNAMERecord) answers[i].first();
			curname = cname.getTarget();
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
			haveAnswer = true;
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
		int cachetype = (rcode == Rcode.NXDOMAIN) ? 0 : qtype;
		if (soa != null || ns == null) {
			/* Negative response */
			cred = getCred(Section.AUTHORITY, isAuth);
			SOARecord soarec = null;
			if (soa != null)
				soarec = (SOARecord) soa.first();
			addNegative(curname, cachetype, soarec, cred);
			if (response == null) {
				int responseType;
				if (rcode == Rcode.NXDOMAIN)
					responseType = SetResponse.NXDOMAIN;
				else
					responseType = SetResponse.NXRRSET;
				response = SetResponse.ofType(responseType);
			}
			/* NXT records are not cached yet. */
		} else {
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
		int type = addl[i].getType();
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
flushSet(Name name, int type) {
	removeElement(name, type);
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
 * Sets the maximum length of time that a negative response will be stored
 * in this Cache.  A negative value disables this feature (that is, sets
 * no limit).
 */
public void
setMaxNCache(int seconds) {
	maxncache = seconds;
}

/**
 * Sets the maximum length of time that records will be stored in this
 * Cache.  A negative value disables this feature (that is, sets no limit).
 */
public void
setMaxCache(int seconds) {
	maxcache = seconds;
}

/**
 * Sets the periodic interval (in minutes) that all expired records will be
 * expunged from the cache.  The default is 30 minutes.  0 or a negative value
 * disables this feature.
 * @param cleanInterval The interval between cache cleanings, in minutes.
 */
public void
setCleanInterval(int cleanInterval) {
	if (cleaner != null) {
		cleaner.interrupt();
	}
	if (cleanInterval > 0)
		cleaner = new CacheCleaner(this, cleanInterval);
}

protected void
finalize() throws Throwable {
	try {
		setCleanInterval(0);
	}
	finally {
		super.finalize();
	}
}

}

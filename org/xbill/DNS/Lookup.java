// Copyright (c) 2002 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import java.net.*;

/**
 * The Lookup object performs queries at a high level.  The input consists
 * of a name, an optional type, and an optional class.  Caching is used
 * when possible to reduce the number of DNS requests, and a Resolver
 * is used to perform the queries.  A search path can be set or determined
 * by FindServer, which allows lookups of unqualified names.
 * @see Cache
 * @see Resolver
 * @see FindServer
 *
 * @author Brian Wellington
 */

public final class Lookup {

private static Resolver defaultResolver;
private static Name [] defaultSearchPath;
private static Map defaultCaches;

private Resolver resolver;
private Name [] searchPath;
private Cache cache;
private byte credibility;
private Name name;
private short type;
private short dclass;
private boolean verbose;
private int iterations;
private boolean found;
private boolean done;
private List aliases;
private Record [] answers;
private int result;
private String error;
private boolean nxdomain;
private boolean badresponse;
private boolean networkerror;
private boolean nametoolong;

/** The lookup was successful. */
public static final int SUCCESSFUL = 0;

/**
 * The lookup failed due to a data or server error. Repeating the lookup
 * would not be helpful.
 */
public static final int UNRECOVERABLE = 1;

/**
 * The lookup failed due to a network error. Repeating the lookup may be
 * helpful.
 */
public static final int TRY_AGAIN = 2;

/** The host does not exist. */
public static final int HOST_NOT_FOUND = 3;

/** The host exists, but has no records associated with the queried type. */
public static final int TYPE_NOT_FOUND = 4;

static {
	try {
		defaultResolver = new ExtendedResolver();
	}
	catch (UnknownHostException e) {
		throw new RuntimeException("Failed to initialize resolver");
	}
	defaultSearchPath = FindServer.searchPath();
	defaultCaches = new HashMap();
}

/**
 * Gets the Resolver that will be used as the default by future Lookups.
 * @return The default resolver.
 */
public static synchronized Resolver
getDefaultResolver() {
	return defaultResolver;
}

/**
 * Sets the Resolver that will be used as the default by future Lookups.
 * @param resolver The default resolver.
 */
public static synchronized void
setDefaultResolver(Resolver resolver) {
	defaultResolver = resolver;
}

/**
 * Gets the Cache that will be used as the default for the specified
 * class by future Lookups.
 * @param dclass The class whose cache is being retrieved.
 * @return The default cache for the specified class.
 */
public static synchronized Cache
getDefaultCache(short dclass) {
	Cache c = (Cache) defaultCaches.get(DClass.toShort(dclass));
	if (c == null) {
		c = new Cache(dclass);
		defaultCaches.put(DClass.toShort(dclass), c);
	}
	return c;
}

/**
 * Sets the Cache that will be used as the default for the specified
 * class by future Lookups.
 * @param cache The default cache for the specified class.
 * @param dclass The class whose cache is being set.
 */
public static synchronized void
setDefaultCache(Cache cache, short dclass) {
	defaultCaches.put(DClass.toShort(dclass), cache);
}

/**
 * Gets the search path that will be used as the default by future Lookups.
 * @return The default search path.
 */
public static synchronized Name []
getDefaultSearchPath() {
	return defaultSearchPath;
}

/**
 * Sets the search path that will be used as the default by future Lookups.
 * @param domains The default search path.
 */
public static synchronized void
setDefaultSearchPath(Name [] domains) {
	defaultSearchPath = domains;
}

/**
 * Sets the search path that will be used as the default by future Lookups.
 * @param domains The default search path.
 * @throws TextParseException A name in the array is not a valid DNS name.
 */
public static synchronized void
setDefaultSearchPath(String [] domains) throws TextParseException {
	if (domains == null) {
		defaultSearchPath = null;
		return;
	}
	Name [] newdomains = new Name[domains.length];
	for (int i = 0; i < domains.length; i++)
		newdomains[i] = Name.fromString(domains[i], Name.root);
	defaultSearchPath = newdomains;
}

/**
 * Create a Lookup object that will find records of the given name, type,
 * and class.  The lookup will use the default cache, resolver, and search
 * path, and look for records that are reasonably credible.
 * @param name The name of the desired records
 * @param type The type of the desired records
 * @param dclass The class of the desired records
 * @throws IllegalArgumentException The type is a meta type other than ANY.
 * @see Cache
 * @see Resolver
 * @see Credibility
 * @see Name
 * @see Type
 * @see DClass
 */
public
Lookup(Name name, short type, short dclass) {
	if (!Type.isRR(type) && type != Type.ANY)
		throw new IllegalArgumentException("Cannot query for " +
						   "meta-types other than ANY");
	this.name = name;
	this.type = type;
	this.dclass = dclass;
	synchronized (Lookup.class) {
		this.resolver = defaultResolver;
		this.searchPath = defaultSearchPath;
		this.cache = getDefaultCache(dclass);
	}
	this.credibility = Credibility.NORMAL;
	this.verbose = Options.check("verbose");
	this.result = -1;
	this.aliases = new ArrayList();
}

/**
 * Create a Lookup object that will find records of the given name and type
 * in the IN class.
 * @param name The name of the desired records
 * @param type The type of the desired records
 * @throws IllegalArgumentException The type is a meta type other than ANY.
 * @see #Lookup(Name,short,short)
 */
public
Lookup(Name name, short type) {
	this(name, type, DClass.IN);
}

/**
 * Create a Lookup object that will find records of type A at the given name
 * in the IN class.
 * @param name The name of the desired records
 * @see #Lookup(Name,short,short)
 */
public
Lookup(Name name) {
	this(name, Type.A, DClass.IN);
}

/**
 * Create a Lookup object that will find records of the given name, type,
 * and class.
 * @param name The name of the desired records
 * @param type The type of the desired records
 * @param dclass The class of the desired records
 * @throws TextParseException The name is not a valid DNS name
 * @throws IllegalArgumentException The type is a meta type other than ANY.
 * @see #Lookup(Name,short,short)
 */
public
Lookup(String name, short type, short dclass) throws TextParseException {
	this(Name.fromString(name), type, dclass);
}

/**
 * Create a Lookup object that will find records of the given name and type
 * in the IN class.
 * @param name The name of the desired records
 * @param type The type of the desired records
 * @throws TextParseException The name is not a valid DNS name
 * @throws IllegalArgumentException The type is a meta type other than ANY.
 * @see #Lookup(Name,short,short)
 */
public
Lookup(String name, short type) throws TextParseException {
	this(Name.fromString(name), type, DClass.IN);
}

/**
 * Create a Lookup object that will find records of type A at the given name
 * in the IN class.
 * @param name The name of the desired records
 * @throws TextParseException The name is not a valid DNS name
 * @see #Lookup(Name,short,short)
 */
public
Lookup(String name) throws TextParseException {
	this(Name.fromString(name), Type.A, DClass.IN);
}

/**
 * Sets the resolver to use when performing the lookup.
 * @param resolver The resolver to use.
 */
public void
setResolver(Resolver resolver) {
	this.resolver = resolver;
}

/**
 * Sets the search path to use when performing the lookup.
 * @param domains An array of names containing the search path.
 */
public void
setSearchPath(Name [] domains) {
	this.searchPath = domains;
}

/**
 * Sets the search path to use when performing the lookup.
 * @param domains An array of names containing the search path.
 * @throws TextParseException A name in the array is not a valid DNS name.
 */
public void
setSearchPath(String [] domains) throws TextParseException {
	if (domains == null) {
		this.searchPath = null;
		return;
	}
	Name [] newdomains = new Name[domains.length];
	for (int i = 0; i < domains.length; i++)
		newdomains[i] = Name.fromString(domains[i], Name.root);
	this.searchPath = newdomains;
}

/**
 * Sets the cache to use when performing the lookup.  If the results of this
 * lookup should not be permanently cached, a temporary cache or null can
 * be provided here.
 * @param cache The cache to use.
 */
public void
setCache(Cache cache) {
	if (cache == null)
		cache = new Cache(dclass);
	this.cache = cache;
}

/**
 * Sets the minimum credibility level that will be accepted when performing
 * the lookup.
 * @param credibility The minimum credibility level.
 */
public void
setCredibility(byte credibility) {
	this.credibility = credibility;
}

private void
follow(Name name, Name oldname) {
	found = true;
	badresponse = false;
	networkerror = false;
	nxdomain = false;
	iterations++;
	if (iterations >= 6 || name.equals(oldname)) {
		result = UNRECOVERABLE;
		error = "CNAME loop";
		return;
	}
	aliases.add(name);
	lookup(name);
}

private void
processResponse(Name name, SetResponse response) {
	if (response.isSuccessful()) {
		RRset [] rrsets = response.answers();
		List l = new ArrayList();
		Iterator it;
		int i;

		for (i = 0; i < rrsets.length; i++) {
			it = rrsets[i].rrs();
			while (it.hasNext())
				l.add(it.next());
		}

		result = SUCCESSFUL;
		answers = (Record []) l.toArray(new Record[l.size()]);
		done = true;
	} else if (response.isNXDOMAIN()) {
		nxdomain = true;
	} else if (response.isNXRRSET()) {
		result = TYPE_NOT_FOUND;
		answers = null;
		done = true;
	} else if (response.isCNAME()) {
		CNAMERecord cname = response.getCNAME();
		follow(cname.getTarget(), name);
	} else if (response.isDNAME()) {
		DNAMERecord dname = response.getDNAME();
		Name newname = null;
		try {
			follow(name.fromDNAME(dname), name);
		} catch (NameTooLongException e) {
			result = UNRECOVERABLE;
			error = "Invalid DNAME target";
			done = true;
		}
	}
}

private void
lookup(Name current) {
	SetResponse sr = cache.lookupRecords(current, type, credibility);
	if (verbose) {
		System.err.println("lookup " + current + " " +
				   Type.string(type));
		System.err.println(sr);
	}
	processResponse(current, sr);
	if (done)
		return;

	Record question = Record.newRecord(current, type, dclass);
	Message query = Message.newQuery(question);
	Message response = null;
	try {
		response = resolver.send(query);
	}
	catch (IOException e) {
		// A network error occurred.  Press on.
		networkerror = true;
		return;
	}
	short rcode = response.getHeader().getRcode();
	if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
		// The server we contacted is broken or otherwise unhelpful.
		// Press on.
		badresponse = true;
		return;
	}

	sr = cache.addMessage(response);
	if (sr == null)
		sr = cache.lookupRecords(current, type, credibility);
	if (verbose) {
		System.err.println("queried " + current + " " +
				   Type.string(type));
		System.err.println(sr);
	}
	processResponse(current, sr);
}

private void
resolve(Name current, Name suffix) {
	Name tname = null;
	if (suffix == null)
		tname = current;
	else {
		try {
			tname = Name.concatenate(current, suffix);
		}
		catch (NameTooLongException e) {
			nametoolong = true;
			return;
		}
	}
	lookup(tname);
	if (found)
		done = true;
}

/**
 * Performs the lookup.
 * @return The answers, or null if none are found.
 */
public Record []
run() {
	if (name.isAbsolute())
		resolve(name, null);
	else if (searchPath == null)
		resolve(name, Name.root);
	else {
		if (name.labels() > 1)
			resolve(name, Name.root);
		if (done)
			return answers;

		for (int i = 0; i < searchPath.length; i++) {
			resolve(name, searchPath[i]);
			if (done)
				return answers;
		}

		if (name.labels() <= 1) {
			resolve(name, Name.root);
		}
	}
	if (!done) {
		if (badresponse) {
			result = UNRECOVERABLE;
			error = "bad response";
			done = true;
		} else if (networkerror) {
			result = TRY_AGAIN;
			error = "network error";
			done = true;
		} else if (nxdomain) {
			result = HOST_NOT_FOUND;
			done = true;
		} else if (nametoolong) {
			result = UNRECOVERABLE;
			error = "name too long";
			done = true;
		}
			
	}
	return answers;
}

/**
 * Returns the answers from the lookup.
 * @return The answers, or null if none are found.
 * @throws IllegalStateException The lookup has not completed.
 */
public Record []
getAnswers() {
	if (!done || result == -1)
		throw new IllegalStateException("Lookup isn't done");
	return answers;
}

/**
 * Returns all known aliases for this name.  Whenever a CNAME/DNAME is
 * followed, an alias is added.
 * @return The aliases.
 * @throws IllegalStateException The lookup has not completed.
 */
public Name []
getAliases() {
	if (!done || result == -1)
		throw new IllegalStateException("Lookup isn't done");
	return (Name []) aliases.toArray(new Name[aliases.size()]);
}

/**
 * Returns the result code of the lookup.
 * @return The result code, which can be SUCCESSFUL, UNRECOVERABLE, TRY_AGAIN,
 * HOST_NOT_FOUND, or TYPE_NOT_FOUND.
 * @throws IllegalStateException The lookup has not completed.
 */
public int
getResult() {
	if (!done || result == -1)
		throw new IllegalStateException("Lookup isn't done");
	return result;
}

/**
 * Returns an error string describing the result code of this lookup.
 * @return A string, which may either directly correspond the result code
 * or be more specific.
 * @throws IllegalStateException The lookup has not completed.
 */
public String
getErrorString() {
	if (!done || result == -1)
		throw new IllegalStateException("Lookup isn't done");
	if (error != null)
		return error;
	switch (result) {
		case SUCCESSFUL:	return "successful";
		case UNRECOVERABLE:	return "unrecoverable error";
		case TRY_AGAIN:		return "try again";
		case HOST_NOT_FOUND:	return "host not found";
		case TYPE_NOT_FOUND:	return "type not found";
	}
	return null;
}

}

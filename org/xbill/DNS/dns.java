// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

/* High level API */

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import java.net.*;

/**
 * A high level API for mapping queries to DNS Records.  This is basically
 * a wrapper around the Lookup class.
 * @see Lookup
 *
 * @author Brian Wellington
 */

public final class dns {

private static Resolver res;
private static Map caches;
private static Name [] searchPath;
private static boolean searchPathSet;
private static boolean initialized;

/* Otherwise the class could be instantiated */
private
dns() {}

/**
 * Converts an InetAddress into the corresponding domain name
 * (127.0.0.1 -> 1.0.0.127.IN-ADDR.ARPA.)
 * @return A String containing the domain name.
 */
public static String
inaddrString(InetAddress addr) {
	byte [] address = addr.getAddress();
	StringBuffer sb = new StringBuffer();
	for (int i = 3; i >= 0; i--) {
		sb.append(address[i] & 0xFF);
		sb.append(".");
	}
	sb.append("IN-ADDR.ARPA.");
	return sb.toString();
}

/**
 * Converts an String containing an IP address in dotted quad form into the
 * corresponding domain name.
 * ex. 127.0.0.1 -> 1.0.0.127.IN-ADDR.ARPA.
 * @return A String containing the domain name.
 */
public static String
inaddrString(String s) {
	InetAddress address;
	try {
		address = InetAddress.getByName(s);
	}
	catch (UnknownHostException e) {
		return null;
	}
	return inaddrString(address);
}

/**
 * Sets the Resolver to be used by functions in the dns class
 */
public static synchronized void
setResolver(Resolver res) {
	Lookup.setDefaultResolver(res);
}

/**
 * Obtains the Resolver used by functions in the dns class.  This can be used
 * to set Resolver properties.
 */
public static synchronized Resolver
getResolver() {
	return Lookup.getDefaultResolver();
}

/**
 * Specifies the domains which will be appended to unqualified names before
 * beginning the lookup process.  If this is not set, FindServer will be used.
 * Unlike the Lookup setSearchPath function, this will silently ignore
 * invalid names.
 * @see FindServer
 */
public static synchronized void
setSearchPath(String [] domains) {
	if (domains == null || domains.length == 0) {
		Lookup.setDefaultSearchPath((Name []) null);
		return;
	}

	List l = new ArrayList();
	for (int i = 0; i < domains.length; i++) {
		try {
			l.add(Name.fromString(domains[i], Name.root));
		}
		catch (TextParseException e) {
		}
	}
	searchPath = (Name [])l.toArray(new Name[l.size()]);
	Lookup.setDefaultSearchPath(searchPath);
}

/**
 * Obtains the Cache used by functions in the dns class.  This can be used
 * to perform more specific queries and/or remove elements.
 *
 * @param dclass The dns class of data in the cache
 */
public static synchronized Cache
getCache(int dclass) {
	return Lookup.getDefaultCache(dclass);
}

/**
 * Obtains the (class IN) Cache used by functions in the dns class.  This
 * can be used to perform more specific queries and/or remove elements.
 *
 * @param dclass The dns class of data in the cache
 */
public static synchronized Cache
getCache() {
	return Lookup.getDefaultCache(DClass.IN);
}

/**
 * Finds records with the given name, type, and class with a certain credibility
 * @param namestr The name of the desired records
 * @param type The type of the desired records
 * @param dclass The class of the desired records
 * @param cred The minimum credibility of the desired records
 * @see Credibility
 * @return The matching records, or null if none are found
 */
public static Record []
getRecords(String namestr, int type, int dclass, byte cred) {
	try {
		Lookup lookup = new Lookup(namestr, type, dclass);
		lookup.setCredibility(cred);
		return lookup.run();
	} catch (Exception e) {
		return null;
	}
}

/**
 * Finds credible records with the given name, type, and class
 * @param namestr The name of the desired records
 * @param type The type of the desired records
 * @param dclass The class of the desired records
 * @return The matching records, or null if none are found
 */
public static Record []
getRecords(String namestr, int type, int dclass) {
	return getRecords(namestr, type, dclass, Credibility.NORMAL);
}

/**
 * Finds any records with the given name, type, and class
 * @param namestr The name of the desired records
 * @param type The type of the desired records
 * @param dclass The class of the desired records
 * @return The matching records, or null if none are found
 */
public static Record []
getAnyRecords(String namestr, int type, int dclass) {
	return getRecords(namestr, type, dclass, Credibility.ANY);
}

/**
 * Finds credible records with the given name and type in class IN
 * @param namestr The name of the desired records
 * @param type The type of the desired records
 * @return The matching records, or null if none are found
 */
public static Record []
getRecords(String name, int type) {
	return getRecords(name, type, DClass.IN, Credibility.NORMAL);
}

/**
 * Finds any records with the given name and type in class IN
 * @param namestr The name of the desired records
 * @param type The type of the desired records
 * @return The matching records, or null if none are found
 */
public static Record []
getAnyRecords(String name, int type) {
	return getRecords(name, type, DClass.IN, Credibility.ANY);
}

/**
 * Finds credible records for the given dotted quad address and type in class IN
 * @param addr The dotted quad address of the desired records
 * @param type The type of the desired records
 * @return The matching records, or null if none are found
 */
public static Record []
getRecordsByAddress(String addr, int type) {
	String name = inaddrString(addr);
	return getRecords(name, type, DClass.IN, Credibility.NORMAL);
}

/**
 * Finds any records for the given dotted quad address and type in class IN
 * @param addr The dotted quad address of the desired records
 * @param type The type of the desired records
 * @return The matching records, or null if none are found
 */
public static Record []
getAnyRecordsByAddress(String addr, int type) {
	String name = inaddrString(addr);
	return getRecords(name, type, DClass.IN, Credibility.ANY);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.HashMap;

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */

public final class Type {

/** Address */
public static final int A		= 1;

/** Name server */
public static final int NS		= 2;

/** Mail destination */
public static final int MD		= 3;

/** Mail forwarder */
public static final int MF		= 4;

/** Canonical name (alias) */
public static final int CNAME		= 5;

/** Start of authority */
public static final int SOA		= 6;

/** Mailbox domain name */
public static final int MB		= 7;

/** Mail group member */
public static final int MG		= 8;

/** Mail rename name */
public static final int MR		= 9;

/** Null record */
public static final int NULL		= 10;

/** Well known services */
public static final int WKS		= 11;

/** Domain name pointer */
public static final int PTR		= 12;

/** Host information */
public static final int HINFO		= 13;

/** Mailbox information */
public static final int MINFO		= 14;

/** Mail routing information */
public static final int MX		= 15;

/** Text strings */
public static final int TXT		= 16;

/** Responsible person */
public static final int RP		= 17;

/** AFS cell database */
public static final int AFSDB		= 18;

/** X_25 calling address */
public static final int X25		= 19;

/** ISDN calling address */
public static final int ISDN		= 20;

/** Router */
public static final int RT		= 21;

/** NSAP address */
public static final int NSAP		= 22;

/** Reverse NSAP address (deprecated) */
public static final int NSAP_PTR	= 23;

/** Signature */
public static final int SIG		= 24;

/** Key */
public static final int KEY		= 25;

/** X.400 mail mapping */
public static final int PX		= 26;

/** Geographical position (withdrawn) */
public static final int GPOS		= 27;

/** IPv6 address */
public static final int AAAA		= 28;

/** Location */
public static final int LOC		= 29;

/** Next valid name in zone */
public static final int NXT		= 30;

/** Endpoint identifier */
public static final int EID		= 31;

/** Nimrod locator */
public static final int NIMLOC		= 32;

/** Server selection */
public static final int SRV		= 33;

/** ATM address */
public static final int ATMA		= 34;

/** Naming authority pointer */
public static final int NAPTR		= 35;

/** Key exchange */
public static final int KX		= 36;

/** Certificate */
public static final int CERT		= 37;

/** IPv6 address (experimental) */
public static final int A6		= 38;

/** Non-terminal name redirection */
public static final int DNAME		= 39;

/** Options - contains EDNS metadata */
public static final int OPT		= 41;

/** Address Prefix List */
public static final int APL		= 42;

/** Delegation Signer */
public static final int DS		= 43;

/** Transaction key - used to compute a shared secret or exchange a key */
public static final int TKEY		= 249;

/** Transaction signature */
public static final int TSIG		= 250;

/** Incremental zone transfer */
public static final int IXFR		= 251;

/** Zone transfer */
public static final int AXFR		= 252;

/** Transfer mailbox records */
public static final int MAILB		= 253;

/** Transfer mail agent records */
public static final int MAILA		= 254;

/** Matches any type */
public static final int ANY		= 255;

private static class DoubleHashMap {
	private HashMap byString, byInteger;

	public
	DoubleHashMap() {
		byString = new HashMap();
		byInteger = new HashMap();
	}

	public void
	put(int value, String string) {
		Integer i = Type.toInteger(value);
		byInteger.put(i, string);
		byString.put(string, i);
	}

	public Integer
	getValue(String string) {
		return (Integer) byString.get(string);
	}

	public String
	getString(int value) {
		return (String) byInteger.get(Type.toInteger(value));
	}
}

private static DoubleHashMap types = new DoubleHashMap();
private static Integer [] typecache = new Integer[44];

static {
	for (int i = 0; i < typecache.length; i++)
		typecache[i] = new Integer(i);
	types.put(A, "A");
	types.put(NS, "NS");
	types.put(MD, "MD");
	types.put(MF, "MF");
	types.put(CNAME, "CNAME");
	types.put(SOA, "SOA");
	types.put(MB, "MB");
	types.put(MG, "MG");
	types.put(MR, "MR");
	types.put(NULL, "NULL");
	types.put(WKS, "WKS");
	types.put(PTR, "PTR");
	types.put(HINFO, "HINFO");
	types.put(MINFO, "MINFO");
	types.put(MX, "MX");
	types.put(TXT, "TXT");
	types.put(RP, "RP");
	types.put(AFSDB, "AFSDB");
	types.put(X25, "X25");
	types.put(ISDN, "ISDN");
	types.put(RT, "RT");
	types.put(NSAP, "NSAP");
	types.put(NSAP_PTR, "NSAP_PTR");
	types.put(SIG, "SIG");
	types.put(KEY, "KEY");
	types.put(PX, "PX");
	types.put(GPOS, "GPOS");
	types.put(AAAA, "AAAA");
	types.put(LOC, "LOC");
	types.put(NXT, "NXT");
	types.put(EID, "EID");
	types.put(NIMLOC, "NIMLOC");
	types.put(SRV, "SRV");
	types.put(ATMA, "ATMA");
	types.put(NAPTR, "NAPTR");
	types.put(KX, "KX");
	types.put(CERT, "CERT");
	types.put(A6, "A6");
	types.put(DNAME, "DNAME");
	types.put(OPT, "OPT");
	types.put(APL, "APL");
	types.put(DS, "DS");
	types.put(TKEY, "TKEY");
	types.put(TSIG, "TSIG");
	types.put(IXFR, "IXFR");
	types.put(AXFR, "AXFR");
	types.put(MAILB, "MAILB");
	types.put(MAILA, "MAILA");
	types.put(ANY, "ANY");
}

private
Type() {
}

static void
check(int i) {
	if (i < 0 || i > 0xFFFF)
		throw new InvalidTypeException(i);
}

/**
 * Converts a numeric Type into a String
 * @return The canonical string representation of the type
 * @throws InvalidTypeException The type is out of range.
 */
public static String
string(int i) {
	check(i);
	String s = types.getString(i);
	return (s != null) ? s : ("TYPE" + i);
}

/**
 * Converts a String representation of an Type into its numeric value
 * @return The type code, or -1 on error.
 */
public static int
value(String s) {
	s = s.toUpperCase();
	Integer val = types.getValue(s);
	if (val != null)
		return val.intValue();
	if (s.startsWith("TYPE")) {
		try {
			int type = Integer.parseInt(s.substring(4));
			if (type < 0 || type > 0xFFFF)
				return -1;
			return type;
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
	return -1;
}

/** Is this type valid for a record (a non-meta type)? */
public static boolean
isRR(int type) {
	switch (type) {
		case OPT:
		case TKEY:
		case TSIG:
		case IXFR:
		case AXFR:
		case MAILB:
		case MAILA:
		case ANY:
			return false;
		default:
			return true;
	}
}

/* Converts a type into an Integer, for use in HashMaps, etc. */
static Integer
toInteger(int type) {
	if (type >= 0 && type < typecache.length)
		return (typecache[type]);
	return new Integer(type);
}

}

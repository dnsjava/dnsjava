// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.HashMap;
import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */

public final class Type {

/** Address */
public static final short A		= 1;

/** Name server */
public static final short NS		= 2;

/** Mail destination */
public static final short MD		= 3;

/** Mail forwarder */
public static final short MF		= 4;

/** Canonical name (alias) */
public static final short CNAME		= 5;

/** Start of authority */
public static final short SOA		= 6;

/** Mailbox domain name */
public static final short MB		= 7;

/** Mail group member */
public static final short MG		= 8;

/** Mail rename name */
public static final short MR		= 9;

/** Null record */
public static final short NULL		= 10;

/** Well known services */
public static final short WKS		= 11;

/** Domain name pointer */
public static final short PTR		= 12;

/** Host information */
public static final short HINFO		= 13;

/** Mailbox information */
public static final short MINFO		= 14;

/** Mail routing information */
public static final short MX		= 15;

/** Text strings */
public static final short TXT		= 16;

/** Responsible person */
public static final short RP		= 17;

/** AFS cell database */
public static final short AFSDB		= 18;

/** X_25 calling address */
public static final short X25		= 19;

/** ISDN calling address */
public static final short ISDN		= 20;

/** Router */
public static final short RT		= 21;

/** NSAP address */
public static final short NSAP		= 22;

/** Reverse NSAP address (deprecated) */
public static final short NSAP_PTR	= 23;

/** Signature */
public static final short SIG		= 24;

/** Key */
public static final short KEY		= 25;

/** X.400 mail mapping */
public static final short PX		= 26;

/** Geographical position (withdrawn) */
public static final short GPOS		= 27;

/** IPv6 address */
public static final short AAAA		= 28;

/** Location */
public static final short LOC		= 29;

/** Next valid name in zone */
public static final short NXT		= 30;

/** Endpoint identifier */
public static final short EID		= 31;

/** Nimrod locator */
public static final short NIMLOC	= 32;

/** Server selection */
public static final short SRV		= 33;

/** ATM address */
public static final short ATMA		= 34;

/** Naming authority pointer */
public static final short NAPTR		= 35;

/** Key exchange */
public static final short KX		= 36;

/** Certificate */
public static final short CERT		= 37;

/** IPv6 address (experimental) */
public static final short A6		= 38;

/** Non-terminal name redirection */
public static final short DNAME		= 39;

/** Options - contains EDNS metadata */
public static final short OPT		= 41;

/** Address Prefix List */
public static final short APL		= 42;

/** Delegation Signer */
public static final short DS		= 43;

/** Transaction key - used to compute a shared secret or exchange a key */
public static final short TKEY		= 249;

/** Transaction signature */
public static final short TSIG		= 250;

/** Incremental zone transfer */
public static final short IXFR		= 251;

/** Zone transfer */
public static final short AXFR		= 252;

/** Transfer mailbox records */
public static final short MAILB		= 253;

/** Transfer mail agent records */
public static final short MAILA		= 254;

/** Matches any type */
public static final short ANY		= 255;

private static class DoubleHashMap {
	private HashMap v2s, s2v;

	public
	DoubleHashMap() {
		v2s = new HashMap();
		s2v = new HashMap();
	}

	public void
	put(short value, String string) {
		Short s = Type.toShort(value);
		v2s.put(s, string);
		s2v.put(string, s);
	}

	public Short
	getValue(String string) {
		return (Short) s2v.get(string);
	}

	public String
	getString(short value) {
		return (String) v2s.get(Type.toShort(value));
	}
}

private static DoubleHashMap types = new DoubleHashMap();
private static Short [] typecache = new Short [44];

static {
	for (short i = 0; i < typecache.length; i++)
		typecache[i] = new Short(i);
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

/** Converts a numeric Type into a String */
public static String
string(short i) {
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
	Short val = types.getValue(s);
	if (val != null)
		return val.shortValue();
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

/* Converts a type into a Short, for use in HashMaps, etc. */
static Short
toShort(short type) {
	if (type < typecache.length)
		return (typecache[type]);
	return new Short(type);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */

public final class Type {

private static StringValueTable types = new StringValueTable();

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

/** IPv6 address (old) */
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

/** IPv6 address */
public static final short A6		= 38;

/** Non-terminal name redirection */
public static final short DNAME		= 39;

/** Kitchen sink record - free form binary record (and a bad idea) */
public static final short SINK		= 40;

/** Options - contains EDNS metadata */
public static final short OPT		= 41;

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
public static final short ANY           = 255;

/** Address */

static {
	types.put2(A, "A");
	types.put2(NS, "NS");
	types.put2(MD, "MD");
	types.put2(MF, "MF");
	types.put2(CNAME, "CNAME");
	types.put2(SOA, "SOA");
	types.put2(MB, "MB");
	types.put2(MG, "MG");
	types.put2(MR, "MR");
	types.put2(NULL, "NULL");
	types.put2(WKS, "WKS");
	types.put2(PTR, "PTR");
	types.put2(HINFO, "HINFO");
	types.put2(MINFO, "MINFO");
	types.put2(MX, "MX");
	types.put2(TXT, "TXT");
	types.put2(RP, "RP");
	types.put2(AFSDB, "AFSDB");
	types.put2(X25, "X25");
	types.put2(ISDN, "ISDN");
	types.put2(RT, "RT");
	types.put2(NSAP, "NSAP");
	types.put2(NSAP_PTR, "NSAP_PTR");
	types.put2(SIG, "SIG");
	types.put2(KEY, "KEY");
	types.put2(PX, "PX");
	types.put2(GPOS, "GPOS");
	types.put2(AAAA, "AAAA");
	types.put2(LOC, "LOC");
	types.put2(NXT, "NXT");
	types.put2(EID, "EID");
	types.put2(NIMLOC, "NIMLOC");
	types.put2(SRV, "SRV");
	types.put2(ATMA, "ATMA");
	types.put2(NAPTR, "NAPTR");
	types.put2(KX, "KX");
	types.put2(CERT, "CERT");
	types.put2(A6, "A6");
	types.put2(DNAME, "DNAME");
	types.put2(SINK, "SINK");
	types.put2(OPT, "OPT");
	types.put2(TKEY, "TKEY");
	types.put2(TSIG, "TSIG");
	types.put2(IXFR, "IXFR");
	types.put2(AXFR, "AXFR");
	types.put2(MAILB, "MAILB");
	types.put2(MAILA, "MAILA");
	types.put2(ANY, "ANY");
}

private
Type() {
}

/** Converts a numeric Type into a String */
public static String
string(int i) {
	String s = types.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

/** Converts a String representation of an Type into its numeric value */
public static short
value(String s) {
	short i = (short) types.getValue(s.toUpperCase());
	if (i >= 0)
		return i;
	try {
		return Short.parseShort(s);
	}
	catch (Exception e) {
		return (-1);
	}
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

}

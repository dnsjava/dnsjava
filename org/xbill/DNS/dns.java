// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

/* High level API & routines for string/value conversion */

import java.util.*;
import java.io.*;

public final class dns {

private static Hashtable types = new Hashtable();
private static Hashtable classes = new Hashtable();
private static Hashtable rcodes = new Hashtable();
private static Hashtable opcodes = new Hashtable();
private static Hashtable flags = new Hashtable();
private static Hashtable sections = new Hashtable();
private static Hashtable longSections = new Hashtable();

private static dnsResolver _res;

/* Types */
static final short A		= 1;
static final short NS		= 2;
static final short MD		= 3;
static final short MF		= 4;
static final short CNAME	= 5;
static final short SOA		= 6;
static final short MB		= 7;
static final short MG		= 8;
static final short MR		= 9;
static final short NULL		= 10;
static final short WKS		= 11;
static final short PTR		= 12;
static final short HINFO	= 13;
static final short MINFO	= 14;
static final short MX		= 15;
static final short TXT		= 16;
static final short RP		= 17;
static final short AFSDB	= 18;
static final short X25		= 19;
static final short ISDN		= 20;
static final short RT		= 21;
static final short NSAP		= 22;
static final short NSAP_PTR	= 23;
static final short SIG		= 24;
static final short KEY		= 25;
static final short PX		= 26;
static final short GPOS		= 27;
static final short AAAA		= 28;
static final short LOC		= 29;
static final short NXT		= 30;
static final short EID		= 31;
static final short NIMLOC	= 32;
static final short SRV		= 33;
static final short ATMA		= 34;
static final short NAPTR	= 35;
static final short CERT		= 37;
static final short OPT		= 249;
static final short TSIG		= 250;
static final short IXFR		= 251;
static final short AXFR		= 252;
static final short MAILB	= 253;
static final short MAILA	= 254;

/* Classes */
static final short IN		= 1;
static final short CHAOS	= 3;
static final short HESIOD	= 4;
static final short NONE		= 254;

/* Shared by Type & Class */
static final short ANY		= 255;

/* Rcodes */
static final byte NOERROR = 0;
static final byte FORMERR = 1;
static final byte SERVFAIL = 2;
static final byte NXDOMAIN = 3;
static final byte NOTIMPL = 4;
static final byte REFUSED = 5;
static final byte YXDOMAIN = 6;
static final byte YXRRSET = 7;
static final byte NXRRSET = 8;
static final byte NOTAUTH = 9;
static final byte NOTZONE = 10;
/* TSIG only rcodes */
static final byte BADSIG = 16;
static final byte BADKEY = 17;
static final byte BADTIME = 18;
static final byte BADID = 19;

/* Opcodes */
static final byte QUERY = 0;
static final byte NOTIFY = 4;
static final byte UPDATE = 5;

/* Flags */
static final byte QR = 0;
static final byte AA = 5;
static final byte TC = 6;
static final byte RD = 7;
static final byte RA = 8;
static final byte AD = 10;
static final byte CD = 11;

/* Message sections */
static final byte QUESTION = 0;
static final byte ANSWER = 1;
static final byte AUTHORITY = 2;
static final byte ADDITIONAL = 3;

static final int PORT = 53;

static final String HMAC = "HMAC-MD5.SIG-ALG.REG.INT";

static void
put2(Hashtable h, Object o1, Object o2) {
	h.put(o1, o2);
	h.put(o2, o1);
}

static {
	put2(types, new Short(A), "A");
	put2(types, new Short(NS), "NS");
	put2(types, new Short(MD), "MD");
	put2(types, new Short(MF), "MF");
	put2(types, new Short(CNAME), "CNAME");
	put2(types, new Short(SOA), "SOA");
	put2(types, new Short(MB), "MB");
	put2(types, new Short(MG), "MG");
	put2(types, new Short(MR), "MR");
	put2(types, new Short(NULL), "NULL");
	put2(types, new Short(WKS), "WKS");
	put2(types, new Short(PTR), "PTR");
	put2(types, new Short(HINFO), "HINFO");
	put2(types, new Short(MINFO), "MINFO");
	put2(types, new Short(MX), "MX");
	put2(types, new Short(TXT), "TXT");
	put2(types, new Short(RP), "RP");
	put2(types, new Short(AFSDB), "AFSDB");
	put2(types, new Short(X25), "X25");
	put2(types, new Short(ISDN), "ISDN");
	put2(types, new Short(RT), "RT");
	put2(types, new Short(NSAP), "NSAP");
	put2(types, new Short(NSAP_PTR), "NSAP_PTR");
	put2(types, new Short(SIG), "SIG");
	put2(types, new Short(KEY), "KEY");
	put2(types, new Short(PX), "PX");
	put2(types, new Short(GPOS), "GPOS");
	put2(types, new Short(AAAA), "AAAA");
	put2(types, new Short(LOC), "LOC");
	put2(types, new Short(NXT), "NXT");
	put2(types, new Short(EID), "EID");
	put2(types, new Short(NIMLOC), "NIMLOC");
	put2(types, new Short(SRV), "SRV");
	put2(types, new Short(ATMA), "ATMA");
	put2(types, new Short(NAPTR), "NAPTR");
	put2(types, new Short(CERT), "CERT");
	put2(types, new Short(OPT), "OPT");
	put2(types, new Short(TSIG), "TSIG");
	put2(types, new Short(IXFR), "IXFR");
	put2(types, new Short(AXFR), "AXFR");
	put2(types, new Short(MAILB), "MAILB");
	put2(types, new Short(MAILA), "MAILA");
	put2(types, new Short(ANY), "ANY");

	put2(classes, new Short(IN), "IN");
	put2(classes, new Short(CHAOS), "CHAOS");
	put2(classes, new Short(HESIOD), "HESIOD");
	put2(classes, new Short(NONE), "NONE");
	put2(classes, new Short(ANY), "ANY");

	put2(rcodes, new Byte(NOERROR), "NOERROR");
	put2(rcodes, new Byte(FORMERR), "FORMERR");
	put2(rcodes, new Byte(SERVFAIL), "SERVFAIL");
	put2(rcodes, new Byte(NXDOMAIN), "NXDOMAIN");
	put2(rcodes, new Byte(NOTIMPL), "NOTIMPL");
	put2(rcodes, new Byte(REFUSED), "REFUSED");
	put2(rcodes, new Byte(YXDOMAIN), "YXDOMAIN");
	put2(rcodes, new Byte(YXRRSET), "YXRRSET");
	put2(rcodes, new Byte(NXRRSET), "NXRRSET");
	put2(rcodes, new Byte(NOTAUTH), "NOTAUTH");
	put2(rcodes, new Byte(NOTZONE), "NOTZONE");
	put2(rcodes, new Byte(BADSIG), "BADSIG");
	put2(rcodes, new Byte(BADKEY), "BADKEY");
	put2(rcodes, new Byte(BADTIME), "BADTIME");
	put2(rcodes, new Byte(BADID), "BADID");

	opcodes.put(new Byte(QUERY), "QUERY");
	opcodes.put(new Byte(NOTIFY), "NOTIFY");
	opcodes.put(new Byte(UPDATE), "UPDATE");

	flags.put(new Byte(QR), "qr");
	flags.put(new Byte(AA), "aa");
	flags.put(new Byte(TC), "tc");
	flags.put(new Byte(RD), "rd");
	flags.put(new Byte(RA), "ra");
	flags.put(new Byte(AD), "ad");
	flags.put(new Byte(CD), "cd");

	put2(sections, new Byte(QUESTION), "qd");
	put2(sections, new Byte(ANSWER), "an");
	put2(sections, new Byte(AUTHORITY), "au");
	put2(sections, new Byte(ADDITIONAL), "ad");

	longSections.put(new Byte(QUESTION), "QUESTIONS");
	longSections.put(new Byte(ANSWER), "ANSWERS");
	longSections.put(new Byte(AUTHORITY), "AUTHORITY RECORDS");
	longSections.put(new Byte(ADDITIONAL), "ADDITIONAL RECORDS");

	_res = new dnsResolver();
}

static String
typeString(int i) {
	String s = (String) types.get(new Short((short)i));
	return (s != null) ? s : new Integer(i).toString();
}

static short
typeValue(String s) {
	Short i = (Short) types.get(s.toUpperCase());
	if (i != null)
		return i.shortValue();
	try {
		return Short.parseShort(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

static String
classString(int i) {
	String s = (String) classes.get(new Short((short)i));
	return (s != null) ? s : new Integer(i).toString();
}

static short
classValue(String s) {
	Short i = (Short) classes.get(s.toUpperCase());
	if (i != null)
		return i.shortValue();
	try {
		return Short.parseShort(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

static String
rcodeString(int i) {
	String s = (String) rcodes.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static byte
rcodeValue(String s) {
	Byte i = (Byte) rcodes.get(s.toUpperCase());
	if (i != null)
		return i.byteValue();
	try {
		return Byte.parseByte(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

static String
opcodeString(int i) {
	String s = (String) opcodes.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static String
flagString(int i) {
	/* These values are not flags */
	if ((i >= 1 && i <= 4) || (i >= 12 && i <= 15))
		return null;
	String s = (String) flags.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static String
sectionString(int i) {
	String s = (String) sections.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static byte
sectionValue(String s) {
	Byte i = (Byte) sections.get(s.toLowerCase());
	if (i != null)
		return i.byteValue();
	try {
		return Byte.parseByte(s);
	}
	catch (Exception e) {
		return (-1);
	}
}

static String
longSectionString(int i) {
	String s = (String) longSections.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static dnsRecord []
getRecords(dnsResolver res, String name, short type, short dclass) {
	dnsMessage query = new dnsMessage();
	dnsMessage response;
	dnsRecord question;
	dnsRecord [] answers;
	int answerCount = 0, i = 0;
	Enumeration e;

	query.getHeader().setFlag(dns.RD);
	query.getHeader().setOpcode(dns.QUERY);
	question = dnsRecord.newRecord(new dnsName(name), type, dclass);
	query.addRecord(dns.QUESTION, question);

	try {
		response = res.send(query);
	}
	catch (IOException ioe) {
		return null;
	}

	if (response.getHeader().getRcode() != dns.NOERROR)
		return null;

	e = response.getSection(dns.ANSWER).elements();
	while (e.hasMoreElements()) {
		dnsRecord r = (dnsRecord)e.nextElement();
		if (r.getType() == type)
			answerCount++;
	}

	if (answerCount == 0)
		return null;

	answers = new dnsRecord[answerCount];

	e = response.getSection(dns.ANSWER).elements();
	while (e.hasMoreElements()) {
		dnsRecord r = (dnsRecord)e.nextElement();
		if (r.getType() == type)
			answers[i++] = r;
	}

	return answers;
}

static dnsRecord []
getRecords(dnsResolver res, String name, short type) {
	return getRecords(res, name, type, dns.IN);
}

static dnsRecord []
getRecords(String name, short type, short dclass) {
	return getRecords(_res, name, type, dclass);
}

static dnsRecord []
getRecords(String name, short type) {
	return getRecords(_res, name, type, dns.IN);
}


}

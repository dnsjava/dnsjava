// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import DNS.utils.*;

public final class Type {

private static StringValueTable types = new StringValueTable();

public static final short A		= 1;
public static final short NS		= 2;
public static final short MD		= 3;
public static final short MF		= 4;
public static final short CNAME		= 5;
public static final short SOA		= 6;
public static final short MB		= 7;
public static final short MG		= 8;
public static final short MR		= 9;
public static final short NULL		= 10;
public static final short WKS		= 11;
public static final short PTR		= 12;
public static final short HINFO		= 13;
public static final short MINFO		= 14;
public static final short MX		= 15;
public static final short TXT		= 16;
public static final short RP		= 17;
public static final short AFSDB		= 18;
public static final short X25		= 19;
public static final short ISDN		= 20;
public static final short RT		= 21;
public static final short NSAP		= 22;
public static final short NSAP_PTR	= 23;
public static final short SIG		= 24;
public static final short KEY		= 25;
public static final short PX		= 26;
public static final short GPOS		= 27;
public static final short AAAA		= 28;
public static final short LOC		= 29;
public static final short NXT		= 30;
public static final short EID		= 31;
public static final short NIMLOC	= 32;
public static final short SRV		= 33;
public static final short ATMA		= 34;
public static final short NAPTR		= 35;
public static final short CERT		= 37;
public static final short OPT		= 249;
public static final short TSIG		= 250;
public static final short IXFR		= 251;
public static final short AXFR		= 252;
public static final short MAILB		= 253;
public static final short MAILA		= 254;
public static final short ANY           = 255;

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
	types.put2(CERT, "CERT");
	types.put2(OPT, "OPT");
	types.put2(TSIG, "TSIG");
	types.put2(IXFR, "IXFR");
	types.put2(AXFR, "AXFR");
	types.put2(MAILB, "MAILB");
	types.put2(MAILA, "MAILA");
	types.put2(ANY, "ANY");
}

public static String
string(int i) {
	String s = types.getString(i);
	return (s != null) ? s : new Integer(i).toString();
}

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

public static boolean
isRR(int type) {
	return (type > 0 && type < 128);
}

}

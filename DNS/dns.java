/* Routines for string/value conversion */

import java.util.Hashtable;

public final class dns {

private static Hashtable types = new Hashtable();
private static Hashtable classes = new Hashtable();
private static Hashtable rcodes = new Hashtable();
private static Hashtable opcodes = new Hashtable();
private static Hashtable flags = new Hashtable();
private static Hashtable sections = new Hashtable();
private static Hashtable longSections = new Hashtable();

/* Types */
static final short A	 = 1;
static final short NS	 = 2;
static final short CNAME = 5;
static final short SOA	 = 6;
static final short PTR	 = 12;
static final short MX	 = 15;
static final short TXT	 = 16;
static final short SIG	 = 24;
static final short KEY	 = 25;
static final short NXT	 = 30;
static final short TSIG	 = 250;
static final short AXFR	 = 252;
static final short ANY	 = 255;

/* Classes */
static final short IN	 = 1;
/*static final short ANY = 255;*/

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

static {
	types.put(new Short(A), "A");
	types.put(new Short(NS), "NS");
	types.put(new Short(CNAME), "CNAME");
	types.put(new Short(SOA), "SOA");
	types.put(new Short(PTR), "PTR");
	types.put(new Short(MX), "MX");
	types.put(new Short(TXT), "TXT");
	types.put(new Short(SIG), "SIG");
	types.put(new Short(KEY), "KEY");
	types.put(new Short(NXT), "NXT");
	types.put(new Short(TSIG), "TSIG");
	types.put(new Short(AXFR), "AXFR");
	types.put(new Short(ANY), "ANY");

	types.put("A", new Short(A));
	types.put("NS", new Short(NS));
	types.put("CNAME", new Short(CNAME));
	types.put("SOA", new Short(SOA));
	types.put("PTR", new Short(PTR));
	types.put("MX", new Short(MX));
	types.put("TXT", new Short(TXT));
	types.put("SIG", new Short(SIG));
	types.put("KEY", new Short(KEY));
	types.put("NXT", new Short(NXT));
	types.put("TSIG", new Short(TSIG));
	types.put("AXFR", new Short(AXFR));
	types.put("ANY", new Short(ANY));

	classes.put(new Short(IN), "IN");
	classes.put(new Short(ANY), "ANY");

	classes.put("IN", new Short(IN));
	classes.put("ANY", new Short(ANY));

	rcodes.put(new Byte(NOERROR), "NOERROR");
	rcodes.put(new Byte(FORMERR), "FORMERR");
	rcodes.put(new Byte(SERVFAIL), "SERVFAIL");
	rcodes.put(new Byte(NXDOMAIN), "NXDOMAIN");
	rcodes.put(new Byte(NOTIMPL), "NOTIMPL");
	rcodes.put(new Byte(REFUSED), "REFUSED");
	rcodes.put(new Byte(YXDOMAIN), "YXDOMAIN");
	rcodes.put(new Byte(YXRRSET), "YXRRSET");
	rcodes.put(new Byte(NXRRSET), "NXRRSET");
	rcodes.put(new Byte(NOTAUTH), "NOTAUTH");
	rcodes.put(new Byte(NOTZONE), "NOTZONE");

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

	sections.put(new Byte(QUESTION), "qd");
	sections.put(new Byte(ANSWER), "an");
	sections.put(new Byte(AUTHORITY), "au");
	sections.put(new Byte(ADDITIONAL), "ad");

	longSections.put(new Byte(QUESTION), "QUESTIONS");
	longSections.put(new Byte(ANSWER), "ANSWERS");
	longSections.put(new Byte(AUTHORITY), "AUTHORITY RECORDS");
	longSections.put(new Byte(ADDITIONAL), "ADDITIONAL RECORDS");
}

static String typeString(int i) {
	String s = (String) types.get(new Short((short)i));
	return (s != null) ? s : new Integer(i).toString();
}

static short typeValue(String s) {
	Short i = (Short) types.get(s.toUpperCase());
	return (i != null) ? i.shortValue() : (-1);
}

static String classString(int i) {
	String s = (String) classes.get(new Short((short)i));
	return (s != null) ? s : new Integer(i).toString();
}

static short classValue(String s) {
	Short i = (Short) classes.get(s.toUpperCase());
	return (i != null) ? i.shortValue() : (-1);
}

static String rcodeString(int i) {
	String s = (String) rcodes.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static String opcodeString(int i) {
	String s = (String) opcodes.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static String flagString(int i) {
	/* These values are not flags */
	if ((i >= 1 && i <= 4) || (i >= 12 && i <= 15))
		return null;
	String s = (String) flags.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

static String sectionString(int i) {
	String s = (String) sections.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}
static String longSectionString(int i) {
	String s = (String) longSections.get(new Byte((byte)i));
	return (s != null) ? s : new Integer(i).toString();
}

}

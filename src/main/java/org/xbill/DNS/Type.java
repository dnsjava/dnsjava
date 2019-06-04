// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.HashMap;

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */
public final class Type {

/** {@link ARecord Address} */
public static final int A		= 1;

/** {@link NSRecord Name server} */
public static final int NS		= 2;

/** {@link MDRecord Mail destination} */
public static final int MD		= 3;

/** {@link MFRecord Mail forwarder} */
public static final int MF		= 4;

/** {@link CNAMERecord Canonical name (alias)} */
public static final int CNAME		= 5;

/** {@link SOARecord Start of authority} */
public static final int SOA		= 6;

/** {@link MBRecord Mailbox domain name} */
public static final int MB		= 7;

/** {@link MGRecord Mail group member} */
public static final int MG		= 8;

/** {@link MRRecord Mail rename name} */
public static final int MR		= 9;

/** {@link NULLRecord Null record} */
public static final int NULL		= 10;

/** {@link WKSRecord Well known services} */
public static final int WKS		= 11;

/** {@link PTRRecord Domain name pointer} */
public static final int PTR		= 12;

/** {@link HINFORecord Host information} */
public static final int HINFO		= 13;

/** {@link MINFORecord Mailbox information} */
public static final int MINFO		= 14;

/** {@link MXRecord Mail routing information} */
public static final int MX		= 15;

/** {@link TXTRecord Text strings} */
public static final int TXT		= 16;

/** {@link RPRecord Responsible person} */
public static final int RP		= 17;

/** {@link AFSDBRecord AFS cell database} */
public static final int AFSDB		= 18;

/** {@link X25Record X.25 calling address} */
public static final int X25		= 19;

/** {@link ISDNRecord ISDN calling address} */
public static final int ISDN		= 20;

/** {@link RTRecord Router} */
public static final int RT		= 21;

/** {@link NSAPRecord NSAP address} */
public static final int NSAP		= 22;

/** {@link NSAP_PTRRecord Reverse NSAP address} */
public static final int NSAP_PTR	= 23;

/** {@link SIGRecord Signature} */
public static final int SIG		= 24;

/** {@link KEYRecord Key} */
public static final int KEY		= 25;

/** {@link PXRecord X.400 mail mapping} */
public static final int PX		= 26;

/** {@link GPOSRecord Geographical position} */
public static final int GPOS		= 27;

/** {@link AAAARecord IPv6 address} */
public static final int AAAA		= 28;

/** {@link LOCRecord Location} */
public static final int LOC		= 29;

/** {@link NXTRecord Next valid name in zone} */
public static final int NXT		= 30;

/**
 * Endpoint identifier
 * @see <a href="https://tools.ietf.org/html/draft-ietf-nimrod-dns-00">DNS Resource Records for Nimrod Routing Architecture</a>
 */
public static final int EID		= 31;

/**
 * Nimrod locator
 * @see <a href="https://tools.ietf.org/html/draft-ietf-nimrod-dns-00">DNS Resource Records for Nimrod Routing Architecture</a>
 */
public static final int NIMLOC		= 32;

/** {@link SRVRecord Server selection} */
public static final int SRV		= 33;

/** ATM address */
public static final int ATMA		= 34;

/** {@link NAPTRRecord Naming authority pointer} */
public static final int NAPTR		= 35;

/** {@link KXRecord Key exchange} */
public static final int KX		= 36;

/** {@link CERTRecord Certificate} */
public static final int CERT		= 37;

/** {@link A6Record IPv6 address (historic)} */
public static final int A6		= 38;

/** {@link DNAMERecord Non-terminal name redirection} */
public static final int DNAME		= 39;

/** {@link OPTRecord Options - contains EDNS metadata} */
public static final int OPT		= 41;

/** {@link APLRecord Address Prefix List} */
public static final int APL		= 42;

/** {@link DSRecord Delegation Signer} */
public static final int DS		= 43;

/** {@link SSHFPRecord SSH Key Fingerprint} */
public static final int SSHFP		= 44;

/** {@link IPSECKEYRecord IPSEC key} */
public static final int IPSECKEY	= 45;

/** {@link RRSIGRecord Resource Record Signature} */
public static final int RRSIG		= 46;

/** {@link NSECRecord Next Secure Name} */
public static final int NSEC		= 47;

/** {@link DNSKEYRecord DNSSEC Key} */
public static final int DNSKEY		= 48;

/** {@link DHCIDRecord Dynamic Host Configuration Protocol (DHCP) ID} */
public static final int DHCID		= 49;

/** {@link NSEC3Record Next SECure, 3rd edition} */
public static final int NSEC3		= 50;

/** {@link NSEC3PARAMRecord Next SECure PARAMeter} */
public static final int NSEC3PARAM	= 51;

/** {@link TLSARecord Transport Layer Security Authentication} */
public static final int TLSA		= 52;

/** {@link SMIMEARecord S/MIME cert association} */
public static final int SMIMEA		= 53;

/** {@link CDSRecord Child Delegation Signer} */
public static final int CDS		= 59;

/** {@link CDNSKEYRecord Child DNSKEY} * */
public static final int CDNSKEY		= 60;

/** {@link OPENPGPKEYRecord OpenPGP Key} */
public static final int OPENPGPKEY	= 61;

/** {@link SPFRecord Sender Policy Framework} */
public static final int SPF		= 99;

/** {@link TKEYRecord Transaction key} */
public static final int TKEY		= 249;

/** {@link TSIGRecord Transaction signature} */
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

/** {@link URIRecord URI} */
public static final int URI		= 256;

/** {@link CAARecord Certification Authority Authorization} */
public static final int CAA		= 257;

/** {@link DLVRecord DNSSEC Lookaside Validation} */
public static final int DLV		= 32769;


private static class TypeMnemonic extends Mnemonic {
	private HashMap<Integer, Record> objects;

	public
	TypeMnemonic() {
		super("Type", CASE_UPPER);
		setPrefix("TYPE");
		objects = new HashMap<>();
	}

	public void
	add(int val, String str, Record proto) {
		super.add(val, str);
		objects.put(val, proto);
	}
	
	@Override
	public void
	check(int val) {
		Type.check(val);
	}

	public Record
	getProto(int val) {
		check(val);
		return objects.get(val);
	}
}

private static TypeMnemonic types = new TypeMnemonic();

static {
	types.add(A, "A", new ARecord());
	types.add(NS, "NS", new NSRecord());
	types.add(MD, "MD", new MDRecord());
	types.add(MF, "MF", new MFRecord());
	types.add(CNAME, "CNAME", new CNAMERecord());
	types.add(SOA, "SOA", new SOARecord());
	types.add(MB, "MB", new MBRecord());
	types.add(MG, "MG", new MGRecord());
	types.add(MR, "MR", new MRRecord());
	types.add(NULL, "NULL", new NULLRecord());
	types.add(WKS, "WKS", new WKSRecord());
	types.add(PTR, "PTR", new PTRRecord());
	types.add(HINFO, "HINFO", new HINFORecord());
	types.add(MINFO, "MINFO", new MINFORecord());
	types.add(MX, "MX", new MXRecord());
	types.add(TXT, "TXT", new TXTRecord());
	types.add(RP, "RP", new RPRecord());
	types.add(AFSDB, "AFSDB", new AFSDBRecord());
	types.add(X25, "X25", new X25Record());
	types.add(ISDN, "ISDN", new ISDNRecord());
	types.add(RT, "RT", new RTRecord());
	types.add(NSAP, "NSAP", new NSAPRecord());
	types.add(NSAP_PTR, "NSAP-PTR", new NSAP_PTRRecord());
	types.add(SIG, "SIG", new SIGRecord());
	types.add(KEY, "KEY", new KEYRecord());
	types.add(PX, "PX", new PXRecord());
	types.add(GPOS, "GPOS", new GPOSRecord());
	types.add(AAAA, "AAAA", new AAAARecord());
	types.add(LOC, "LOC", new LOCRecord());
	types.add(NXT, "NXT", new NXTRecord());
	types.add(EID, "EID");
	types.add(NIMLOC, "NIMLOC");
	types.add(SRV, "SRV", new SRVRecord());
	types.add(ATMA, "ATMA");
	types.add(NAPTR, "NAPTR", new NAPTRRecord());
	types.add(KX, "KX", new KXRecord());
	types.add(CERT, "CERT", new CERTRecord());
	types.add(A6, "A6", new A6Record());
	types.add(DNAME, "DNAME", new DNAMERecord());
	types.add(OPT, "OPT", new OPTRecord());
	types.add(APL, "APL", new APLRecord());
	types.add(DS, "DS", new DSRecord());
	types.add(SSHFP, "SSHFP", new SSHFPRecord());
	types.add(IPSECKEY, "IPSECKEY", new IPSECKEYRecord());
	types.add(RRSIG, "RRSIG", new RRSIGRecord());
	types.add(NSEC, "NSEC", new NSECRecord());
	types.add(DNSKEY, "DNSKEY", new DNSKEYRecord());
	types.add(DHCID, "DHCID", new DHCIDRecord());
	types.add(NSEC3, "NSEC3", new NSEC3Record());
	types.add(NSEC3PARAM, "NSEC3PARAM", new NSEC3PARAMRecord());
	types.add(TLSA, "TLSA", new TLSARecord());
	types.add(SMIMEA, "SMIMEA", new SMIMEARecord());
	types.add(CDNSKEY, "CDNSKEY", new CDNSKEYRecord());
	types.add(CDS, "CDS", new CDSRecord());
	types.add(OPENPGPKEY, "OPENPGPKEY", new OPENPGPKEYRecord());
	types.add(SPF, "SPF", new SPFRecord());
	types.add(TKEY, "TKEY", new TKEYRecord());
	types.add(TSIG, "TSIG", new TSIGRecord());
	types.add(IXFR, "IXFR");
	types.add(AXFR, "AXFR");
	types.add(MAILB, "MAILB");
	types.add(MAILA, "MAILA");
	types.add(ANY, "ANY");
	types.add(URI, "URI", new URIRecord());
	types.add(CAA, "CAA", new CAARecord());
	types.add(DLV, "DLV", new DLVRecord());
}

private
Type() {
}

/**
 * Checks that a numeric Type is valid.
 * @throws InvalidTypeException The type is out of range.
 */
public static void
check(int val) {
	if (val < 0 || val > 0xFFFF)
		throw new InvalidTypeException(val);
}

/**
 * Converts a numeric Type into a String
 * @param val The type value.
 * @return The canonical string representation of the type
 * @throws InvalidTypeException The type is out of range.
 */
public static String
string(int val) {
	return types.getText(val);
}

/**
 * Converts a String representation of an Type into its numeric value.
 * @param s The string representation of the type
 * @param numberok Whether a number will be accepted or not.
 * @return The type code, or -1 on error.
 */
public static int
value(String s, boolean numberok) {
	int val = types.getValue(s);
	if (val == -1 && numberok) {
		val = types.getValue("TYPE" + s);
	}
	return val;
}

/**
 * Converts a String representation of an Type into its numeric value
 * @return The type code, or -1 on error.
 */
public static int
value(String s) {
	return value(s, false);
}

static Record
getProto(int val) {
	return types.getProto(val);
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

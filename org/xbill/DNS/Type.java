// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.HashMap;


/********************************************************************
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */

public final
class Type
{
	/** Address */
	static public final int A = 1;

	/** Name server */
	static public final int NS = 2;

	/** Mail destination */
	static public final int MD = 3;

	/** Mail forwarder */
	static public final int MF = 4;

	/** Canonical name (alias) */
	static public final int CNAME = 5;

	/** Start of authority */
	static public final int SOA = 6;

	/** Mailbox domain name */
	static public final int MB = 7;

	/** Mail group member */
	static public final int MG = 8;

	/** Mail rename name */
	static public final int MR = 9;

	/** Null record */
	static public final int NULL = 10;

	/** Well known services */
	static public final int WKS = 11;

	/** Domain name pointer */
	static public final int PTR = 12;

	/** Host information */
	static public final int HINFO = 13;

	/** Mailbox information */
	static public final int MINFO = 14;

	/** Mail routing information */
	static public final int MX = 15;

	/** Text strings */
	static public final int TXT = 16;

	/** Responsible person */
	static public final int RP = 17;

	/** AFS cell database */
	static public final int AFSDB = 18;

	/** X.25 calling address */
	static public final int X25 = 19;

	/** ISDN calling address */
	static public final int ISDN = 20;

	/** Router */
	static public final int RT = 21;

	/** NSAP address */
	static public final int NSAP = 22;

	/** Reverse NSAP address (deprecated) */
	static public final int NSAP_PTR = 23;

	/** Signature */
	static public final int SIG = 24;

	/** Key */
	static public final int KEY = 25;

	/** X.400 mail mapping */
	static public final int PX = 26;

	/** Geographical position (withdrawn) */
	static public final int GPOS = 27;

	/** IPv6 address */
	static public final int AAAA = 28;

	/** Location */
	static public final int LOC = 29;

	/** Next valid name in zone */
	static public final int NXT = 30;

	/** Endpoint identifier */
	static public final int EID = 31;

	/** Nimrod locator */
	static public final int NIMLOC = 32;

	/** Server selection */
	static public final int SRV = 33;

	/** ATM address */
	static public final int ATMA = 34;

	/** Naming authority pointer */
	static public final int NAPTR = 35;

	/** Key exchange */
	static public final int KX = 36;

	/** Certificate */
	static public final int CERT = 37;

	/** IPv6 address (experimental) */
	static public final int A6 = 38;

	/** Non-terminal name redirection */
	static public final int DNAME = 39;

	/** Options - contains EDNS metadata */
	static public final int OPT = 41;

	/** Address Prefix List */
	static public final int APL = 42;

	/** Delegation Signer */
	static public final int DS = 43;

	/** SSH Key Fingerprint */
	static public final int SSHFP = 44;

	/** IPSEC key */
	static public final int IPSECKEY = 45;

	/** Resource Record Signature */
	static public final int RRSIG = 46;

	/** Next Secure Name */
	static public final int NSEC = 47;

	/** DNSSEC Key */
	static public final int DNSKEY = 48;

	/** Dynamic Host Configuration Protocol (DHCP) ID */
	static public final int DHCID = 49;

	/** Next SECure, 3rd edition, RFC 5155 */
	static public final int NSEC3 = 50;

	/** Next SECure PARAMeter, RFC 5155 */
	static public final int NSEC3PARAM = 51;

	/** Transport Layer Security Authentication, draft-ietf-dane-protocol-23 */
	static public final int TLSA = 52;

	/** S/MIME cert association, draft-ietf-dane-smime */
	static public final int SMIMEA = 53;

	/** Child Delegation Signer, RFC 8078 * */
	static public final int CDS = 59;

	/** Child DNSKEY, RFC 8078 * */
	static public final int CDNSKEY = 60;

	/** OpenPGP Key, RFC 7929 */
	static public final int OPENPGPKEY = 61;

	/** Sender Policy Framework (experimental) */
	static public final int SPF = 99;

	/** Transaction key - used to compute a shared secret or exchange a key */
	static public final int TKEY = 249;

	/** Transaction signature */
	static public final int TSIG = 250;

	/** Incremental zone transfer */
	static public final int IXFR = 251;

	/** Zone transfer */
	static public final int AXFR = 252;

	/** Transfer mailbox records */
	static public final int MAILB = 253;

	/** Transfer mail agent records */
	static public final int MAILA = 254;

	/** Matches any type */
	static public final int ANY = 255;

	/**
	 * URI
	 *
	 * @see <a href="http://tools.ietf.org/html/draft-faltstrom-uri-14">draft-faltstrom-uri-14</a>
	 */
	static public final int URI = 256;

	/** Certification Authority Authorization, RFC 6844 */
	static public final int CAA = 257;

	/** DNSSEC Lookaside Validation, RFC 4431 . */
	static public final int DLV = 32769;

	static private TypeMnemonic types = new TypeMnemonic();

	static
	{
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
		types.add(CDNSKEY, "CDNSKEY", new CDNSKEYRecord());
		types.add(CDS, "CDS", new CDSRecord());
	}

	private Type()
	{
	}

	/***************************************
	 * Checks that a numeric Type is valid.
	 *
	 * @throws InvalidTypeException The type is out of range.
	 */
	static public void check(final int val)
	{
		if (val < 0 || val > 0xFFFF)
		{
			throw new InvalidTypeException(val);
		}
	}

	/***************************************
	 * Is this type valid for a record (a non-meta type)?
	 */
	static public boolean isRR(final int type)
	{
		switch (type)
		{
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

	/***************************************
	 * Converts a numeric Type into a String
	 *
	 * @param  val The type value.
	 *
	 * @return The canonical string representation of the type
	 *
	 * @throws InvalidTypeException The type is out of range.
	 */
	static public String string(final int val)
	{
		return types.getText(val);
	}

	/***************************************
	 * Converts a String representation of an Type into its numeric value
	 *
	 * @return The type code, or -1 on error.
	 */
	static public int value(final String s)
	{
		return value(s, false);
	}

	/***************************************
	 * Converts a String representation of an Type into its numeric value.
	 *
	 * @param  s        The string representation of the type
	 * @param  numberok Whether a number will be accepted or not.
	 *
	 * @return The type code, or -1 on error.
	 */
	static public int value(final String s, final boolean numberok)
	{
		int val = types.getValue(s);

		if (val == -1 && numberok)
		{
			val = types.getValue("TYPE" + s);
		}

		return val;
	}

	static Record getProto(final int val)
	{
		return types.getProto(val);
	}

	static private
	class TypeMnemonic extends Mnemonic
	{
		private final HashMap objects;

		public TypeMnemonic()
		{
			super("Type", CASE_UPPER);
			setPrefix("TYPE");
			objects = new HashMap();
		}

		public void add(final int val, final String str, final Record proto)
		{
			super.add(val, str);
			objects.put(Mnemonic.toInteger(val), proto);
		}

		@Override
		public void check(final int val)
		{
			Type.check(val);
		}

		public Record getProto(final int val)
		{
			check(val);

			return (Record) objects.get(toInteger(val));
		}
	}
}

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
  public static final int A = 1;

  /** {@link NSRecord Name server} */
  public static final int NS = 2;

  /** {@link MDRecord Mail destination} */
  public static final int MD = 3;

  /** {@link MFRecord Mail forwarder} */
  public static final int MF = 4;

  /** {@link CNAMERecord Canonical name (alias)} */
  public static final int CNAME = 5;

  /** {@link SOARecord Start of authority} */
  public static final int SOA = 6;

  /** {@link MBRecord Mailbox domain name} */
  public static final int MB = 7;

  /** {@link MGRecord Mail group member} */
  public static final int MG = 8;

  /** {@link MRRecord Mail rename name} */
  public static final int MR = 9;

  /** {@link NULLRecord Null record} */
  public static final int NULL = 10;

  /** {@link WKSRecord Well known services} */
  public static final int WKS = 11;

  /** {@link PTRRecord Domain name pointer} */
  public static final int PTR = 12;

  /** {@link HINFORecord Host information} */
  public static final int HINFO = 13;

  /** {@link MINFORecord Mailbox information} */
  public static final int MINFO = 14;

  /** {@link MXRecord Mail routing information} */
  public static final int MX = 15;

  /** {@link TXTRecord Text strings} */
  public static final int TXT = 16;

  /** {@link RPRecord Responsible person} */
  public static final int RP = 17;

  /** {@link AFSDBRecord AFS cell database} */
  public static final int AFSDB = 18;

  /** {@link X25Record X.25 calling address} */
  public static final int X25 = 19;

  /** {@link ISDNRecord ISDN calling address} */
  public static final int ISDN = 20;

  /** {@link RTRecord Router} */
  public static final int RT = 21;

  /** {@link NSAPRecord NSAP address} */
  public static final int NSAP = 22;

  /** {@link NSAP_PTRRecord Reverse NSAP address} */
  public static final int NSAP_PTR = 23;

  /** {@link SIGRecord Signature} */
  public static final int SIG = 24;

  /** {@link KEYRecord Key} */
  public static final int KEY = 25;

  /** {@link PXRecord X.400 mail mapping} */
  public static final int PX = 26;

  /** {@link GPOSRecord Geographical position} */
  public static final int GPOS = 27;

  /** {@link AAAARecord IPv6 address} */
  public static final int AAAA = 28;

  /** {@link LOCRecord Location} */
  public static final int LOC = 29;

  /** {@link NXTRecord Next valid name in zone} */
  public static final int NXT = 30;

  /**
   * Endpoint identifier
   *
   * @see <a href="https://tools.ietf.org/html/draft-ietf-nimrod-dns-00">DNS Resource Records for
   *     Nimrod Routing Architecture</a>
   */
  public static final int EID = 31;

  /**
   * Nimrod locator
   *
   * @see <a href="https://tools.ietf.org/html/draft-ietf-nimrod-dns-00">DNS Resource Records for
   *     Nimrod Routing Architecture</a>
   */
  public static final int NIMLOC = 32;

  /** {@link SRVRecord Server selection} */
  public static final int SRV = 33;

  /** ATM address */
  public static final int ATMA = 34;

  /** {@link NAPTRRecord Naming authority pointer} */
  public static final int NAPTR = 35;

  /** {@link KXRecord Key exchange} */
  public static final int KX = 36;

  /** {@link CERTRecord Certificate} */
  public static final int CERT = 37;

  /** {@link A6Record IPv6 address (historic)} */
  public static final int A6 = 38;

  /** {@link DNAMERecord Non-terminal name redirection} */
  public static final int DNAME = 39;

  /** Kitchen Sink (April Fools' Day RR) */
  public static final int SINK = 40;

  /** {@link OPTRecord Options - contains EDNS metadata} */
  public static final int OPT = 41;

  /** {@link APLRecord Address Prefix List} */
  public static final int APL = 42;

  /** {@link DSRecord Delegation Signer} */
  public static final int DS = 43;

  /** {@link SSHFPRecord SSH Key Fingerprint} */
  public static final int SSHFP = 44;

  /** {@link IPSECKEYRecord IPSEC key} */
  public static final int IPSECKEY = 45;

  /** {@link RRSIGRecord Resource Record Signature} */
  public static final int RRSIG = 46;

  /** {@link NSECRecord Next Secure Name} */
  public static final int NSEC = 47;

  /** {@link DNSKEYRecord DNSSEC Key} */
  public static final int DNSKEY = 48;

  /** {@link DHCIDRecord Dynamic Host Configuration Protocol (DHCP) ID} */
  public static final int DHCID = 49;

  /** {@link NSEC3Record Next SECure, 3rd edition} */
  public static final int NSEC3 = 50;

  /** {@link NSEC3PARAMRecord Next SECure PARAMeter} */
  public static final int NSEC3PARAM = 51;

  /** {@link TLSARecord Transport Layer Security Authentication} */
  public static final int TLSA = 52;

  /** {@link SMIMEARecord S/MIME cert association} */
  public static final int SMIMEA = 53;

  /** {@link HIPRecord Host Identity Protocol (HIP)} */
  public static final int HIP = 55;

  /**
   * Zone Status (ZS).
   *
   * @see <a href="https://tools.ietf.org/html/draft-reid-dnsext-zs-01">draft-reid-dnsext-zs-01</a>
   */
  public static final int NINFO = 56;

  /**
   * RKEY DNS Resource Record, used for encryption of NAPTR records.
   *
   * @see <a
   *     href="https://tools.ietf.org/html/draft-reid-dnsext-rkey-00">draft-reid-dnsext-rkey-00</a>
   */
  public static final int RKEY = 57;

  /**
   * DNSSEC Trust Anchor History Service.
   *
   * @see <a
   *     href="https://tools.ietf.org/html/draft-wijngaards-dnsop-trust-history-02">draft-wijngaards-dnsop-trust-history-02</a>
   */
  public static final int TALINK = 58;

  /** {@link CDSRecord Child Delegation Signer} */
  public static final int CDS = 59;

  /** {@link CDNSKEYRecord Child DNSKEY} * */
  public static final int CDNSKEY = 60;

  /** {@link OPENPGPKEYRecord OpenPGP Key} */
  public static final int OPENPGPKEY = 61;

  /** Child-to-Parent Synchronization. */
  public static final int CSYNC = 62;

  /** Message Digest for DNS Zones. */
  public static final int ZONEMD = 63;

  /** {@link SPFRecord Sender Policy Framework} */
  public static final int SPF = 99;

  /** IANA-Reserved */
  public static final int UINFO = 100;

  /** IANA-Reserved */
  public static final int UID = 101;

  /** IANA-Reserved */
  public static final int GID = 102;

  /** IANA-Reserved */
  public static final int UNSPEC = 103;

  /** Node Identifier (NID). */
  public static final int NID = 104;

  /** 32-bit Locator value for ILNPv4-capable node. */
  public static final int L32 = 105;

  /** Unsigned 64-bit Locator value for ILNPv6-capable node. */
  public static final int L64 = 106;

  /** Name of a subnetwork for ILNP. */
  public static final int LP = 107;

  /** EUI-48 Address. */
  public static final int EUI48 = 108;

  /** EUI-64 Address. */
  public static final int EUI64 = 109;

  /** {@link TKEYRecord Transaction key} */
  public static final int TKEY = 249;

  /** {@link TSIGRecord Transaction signature} */
  public static final int TSIG = 250;

  /** Incremental zone transfer */
  public static final int IXFR = 251;

  /** Zone transfer */
  public static final int AXFR = 252;

  /** Transfer mailbox records */
  public static final int MAILB = 253;

  /** mail agent RRs (obsolete - {@see MX}) */
  public static final int MAILA = 254;

  /** Matches any type */
  public static final int ANY = 255;

  /** {@link URIRecord URI} */
  public static final int URI = 256;

  /** {@link CAARecord Certification Authority Authorization} */
  public static final int CAA = 257;

  /** Application Visibility and Control */
  public static final int AVC = 258;

  /** Digital Object Architecture */
  public static final int DOA = 259;

  /** Automatic Multicast Tunneling Relay */
  public static final int AMTRELAY = 260;

  /** DNSSEC Trust Authorities */
  public static final int TA = 32768;

  /** {@link DLVRecord DNSSEC Lookaside Validation} */
  public static final int DLV = 32769;

  private static class TypeMnemonic extends Mnemonic {
    private HashMap<Integer, Class<? extends Record>> objects;

    public TypeMnemonic() {
      super("Type", CASE_UPPER);
      setPrefix("TYPE");
      objects = new HashMap<>();
    }

    public void add(int val, String str, Class<? extends Record> proto) {
      super.add(val, str);
      objects.put(val, proto);
    }

    @Override
    public void check(int val) {
      Type.check(val);
    }

    public Class<? extends Record> getProto(int val) {
      check(val);
      return objects.get(val);
    }
  }

  private static TypeMnemonic types = new TypeMnemonic();

  static {
    types.add(A, "A", ARecord.class);
    types.add(NS, "NS", NSRecord.class);
    types.add(MD, "MD", MDRecord.class);
    types.add(MF, "MF", MFRecord.class);
    types.add(CNAME, "CNAME", CNAMERecord.class);
    types.add(SOA, "SOA", SOARecord.class);
    types.add(MB, "MB", MBRecord.class);
    types.add(MG, "MG", MGRecord.class);
    types.add(MR, "MR", MRRecord.class);
    types.add(NULL, "NULL", NULLRecord.class);
    types.add(WKS, "WKS", WKSRecord.class);
    types.add(PTR, "PTR", PTRRecord.class);
    types.add(HINFO, "HINFO", HINFORecord.class);
    types.add(MINFO, "MINFO", MINFORecord.class);
    types.add(MX, "MX", MXRecord.class);
    types.add(TXT, "TXT", TXTRecord.class);
    types.add(RP, "RP", RPRecord.class);
    types.add(AFSDB, "AFSDB", AFSDBRecord.class);
    types.add(X25, "X25", X25Record.class);
    types.add(ISDN, "ISDN", ISDNRecord.class);
    types.add(RT, "RT", RTRecord.class);
    types.add(NSAP, "NSAP", NSAPRecord.class);
    types.add(NSAP_PTR, "NSAP-PTR", NSAP_PTRRecord.class);
    types.add(SIG, "SIG", SIGRecord.class);
    types.add(KEY, "KEY", KEYRecord.class);
    types.add(PX, "PX", PXRecord.class);
    types.add(GPOS, "GPOS", GPOSRecord.class);
    types.add(AAAA, "AAAA", AAAARecord.class);
    types.add(LOC, "LOC", LOCRecord.class);
    types.add(NXT, "NXT", NXTRecord.class);
    types.add(EID, "EID");
    types.add(NIMLOC, "NIMLOC");
    types.add(SRV, "SRV", SRVRecord.class);
    types.add(ATMA, "ATMA");
    types.add(NAPTR, "NAPTR", NAPTRRecord.class);
    types.add(KX, "KX", KXRecord.class);
    types.add(CERT, "CERT", CERTRecord.class);
    types.add(A6, "A6", A6Record.class);
    types.add(DNAME, "DNAME", DNAMERecord.class);
    types.add(SINK, "SINK");
    types.add(OPT, "OPT", OPTRecord.class);
    types.add(APL, "APL", APLRecord.class);
    types.add(DS, "DS", DSRecord.class);
    types.add(SSHFP, "SSHFP", SSHFPRecord.class);
    types.add(IPSECKEY, "IPSECKEY", IPSECKEYRecord.class);
    types.add(RRSIG, "RRSIG", RRSIGRecord.class);
    types.add(NSEC, "NSEC", NSECRecord.class);
    types.add(DNSKEY, "DNSKEY", DNSKEYRecord.class);
    types.add(DHCID, "DHCID", DHCIDRecord.class);
    types.add(NSEC3, "NSEC3", NSEC3Record.class);
    types.add(NSEC3PARAM, "NSEC3PARAM", NSEC3PARAMRecord.class);
    types.add(TLSA, "TLSA", TLSARecord.class);
    types.add(SMIMEA, "SMIMEA", SMIMEARecord.class);

    types.add(HIP, "HIP", HIPRecord.class);
    types.add(NINFO, "NINFO");
    types.add(RKEY, "RKEY");
    types.add(TALINK, "TALINK");
    types.add(CDS, "CDS", CDSRecord.class);
    types.add(CDNSKEY, "CDNSKEY", CDNSKEYRecord.class);
    types.add(OPENPGPKEY, "OPENPGPKEY", OPENPGPKEYRecord.class);
    types.add(CSYNC, "CSYNC");
    types.add(ZONEMD, "ZONEMD");

    types.add(SPF, "SPF", SPFRecord.class);
    types.add(UINFO, "UINFO");
    types.add(UID, "UID");
    types.add(GID, "GID");
    types.add(UNSPEC, "UNSPEC");
    types.add(NID, "NID");
    types.add(L32, "L32");
    types.add(L64, "L64");
    types.add(LP, "LP");
    types.add(EUI48, "EUI48");
    types.add(EUI64, "EUI64");

    types.add(TKEY, "TKEY", TKEYRecord.class);
    types.add(TSIG, "TSIG", TSIGRecord.class);
    types.add(IXFR, "IXFR");
    types.add(AXFR, "AXFR");
    types.add(MAILB, "MAILB");
    types.add(MAILA, "MAILA");
    types.add(ANY, "ANY");
    types.add(URI, "URI", URIRecord.class);
    types.add(CAA, "CAA", CAARecord.class);
    types.add(AVC, "AVC");
    types.add(DOA, "DOA");
    types.add(AMTRELAY, "AMTRELAY");

    types.add(TA, "TA");
    types.add(DLV, "DLV", DLVRecord.class);
  }

  private Type() {}

  /**
   * Checks that a numeric Type is valid.
   *
   * @throws InvalidTypeException The type is out of range.
   */
  public static void check(int val) {
    if (val < 0 || val > 0xFFFF) {
      throw new InvalidTypeException(val);
    }
  }

  /**
   * Converts a numeric Type into a String
   *
   * @param val The type value.
   * @return The canonical string representation of the type
   * @throws InvalidTypeException The type is out of range.
   */
  public static String string(int val) {
    return types.getText(val);
  }

  /**
   * Converts a String representation of an Type into its numeric value.
   *
   * @param s The string representation of the type
   * @param numberok Whether a number will be accepted or not.
   * @return The type code, or -1 on error.
   */
  public static int value(String s, boolean numberok) {
    int val = types.getValue(s);
    if (val == -1 && numberok) {
      val = types.getValue("TYPE" + s);
    }
    return val;
  }

  /**
   * Converts a String representation of an Type into its numeric value
   *
   * @return The type code, or -1 on error.
   */
  public static int value(String s) {
    return value(s, false);
  }

  static Class<? extends Record> getProto(int val) {
    return types.getProto(val);
  }

  /** Is this type valid for a record (a non-meta type)? */
  public static boolean isRR(int type) {
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

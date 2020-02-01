// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants and functions relating to DNS rcodes (error values)
 *
 * @author Brian Wellington
 */
public final class Rcode {
  private static Mnemonic rcodes = new Mnemonic("DNS Rcode", Mnemonic.CASE_UPPER);

  /** No error */
  public static final int NOERROR = 0;

  /** Format error */
  public static final int FORMERR = 1;

  /** Server failure */
  public static final int SERVFAIL = 2;

  /** The name does not exist */
  public static final int NXDOMAIN = 3;

  /** The operation requested is not implemented */
  public static final int NOTIMP = 4;

  /** Deprecated synonym for NOTIMP. */
  @Deprecated public static final int NOTIMPL = 4;

  /** The operation was refused by the server */
  public static final int REFUSED = 5;

  /** The name exists */
  public static final int YXDOMAIN = 6;

  /** The RRset (name, type) exists */
  public static final int YXRRSET = 7;

  /** The RRset (name, type) does not exist */
  public static final int NXRRSET = 8;

  /** The requestor is not authorized to perform this operation */
  public static final int NOTAUTH = 9;

  /** The zone specified is not a zone */
  public static final int NOTZONE = 10;

  /* EDNS extended rcodes */
  /** Unsupported EDNS level */
  public static final int BADVERS = 16;

  /* TSIG/TKEY only rcodes */
  /** The signature is invalid (TSIG/TKEY extended error) */
  public static final int BADSIG = 16;

  /** The key is invalid (TSIG/TKEY extended error) */
  public static final int BADKEY = 17;

  /** The time is out of range (TSIG/TKEY extended error) */
  public static final int BADTIME = 18;

  /** The mode is invalid (TKEY extended error) */
  public static final int BADMODE = 19;

  /** Duplicate key name (TKEY extended error) */
  public static final int BADNAME = 20;

  /** Algorithm not supported (TKEY extended error) */
  public static final int BADALG = 21;

  /** Bad truncation (RFC 4635) */
  public static final int BADTRUNC = 22;

  /** Bad or missing server cookie (RFC 7873) */
  public static final int BADCOOKIE = 23;

  static {
    rcodes.setMaximum(0xFFF);
    rcodes.setPrefix("RESERVED");
    rcodes.setNumericAllowed(true);

    rcodes.add(NOERROR, "NOERROR");
    rcodes.add(FORMERR, "FORMERR");
    rcodes.add(SERVFAIL, "SERVFAIL");
    rcodes.add(NXDOMAIN, "NXDOMAIN");
    rcodes.add(NOTIMP, "NOTIMP");
    rcodes.addAlias(NOTIMP, "NOTIMPL");
    rcodes.add(REFUSED, "REFUSED");
    rcodes.add(YXDOMAIN, "YXDOMAIN");
    rcodes.add(YXRRSET, "YXRRSET");
    rcodes.add(NXRRSET, "NXRRSET");
    rcodes.add(NOTAUTH, "NOTAUTH");
    rcodes.add(NOTZONE, "NOTZONE");
    rcodes.add(BADVERS, "BADVERS");
    rcodes.add(BADKEY, "BADKEY");
    rcodes.add(BADTIME, "BADTIME");
    rcodes.add(BADMODE, "BADMODE");
    rcodes.add(BADNAME, "BADNAME");
    rcodes.add(BADALG, "BADALG");
    rcodes.add(BADTRUNC, "BADTRUNC");
    rcodes.add(BADCOOKIE, "BADCOOKIE");
  }

  private Rcode() {}

  /** Converts a numeric Rcode into a String */
  public static String string(int i) {
    return rcodes.getText(i);
  }

  /** Converts a numeric TSIG extended Rcode into a String */
  public static String TSIGstring(int i) {
    if (i == BADSIG) {
      return "BADSIG";
    }

    return string(i);
  }

  /** Converts a String representation of an Rcode into its numeric value */
  public static int value(String s) {
    if ("BADSIG".equalsIgnoreCase(s)) {
      return BADSIG;
    }

    return rcodes.getValue(s);
  }
}

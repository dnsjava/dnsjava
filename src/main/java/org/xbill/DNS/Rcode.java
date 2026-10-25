// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants and functions relating to DNS rcodes (error values)
 *
 * @author Brian Wellington
 */
public final class Rcode {
  private static final Mnemonic rcodes = new Mnemonic("DNS Rcode", Mnemonic.CASE_UPPER);

  /** No Error. */
  public static final int NOERROR = 0;

  /** Format Error. */
  public static final int FORMERR = 1;

  /** Server Failure. */
  public static final int SERVFAIL = 2;

  /** Non-Existent Domain. */
  public static final int NXDOMAIN = 3;

  /** Not Implemented. */
  public static final int NOTIMP = 4;

  /**
   * Synonym for NOTIMP.
   *
   * @deprecated Use {@link #NOTIMP}.
   */
  @Deprecated public static final int NOTIMPL = 4;

  /** Query Refused. */
  public static final int REFUSED = 5;

  /**
   * Name Exists when it should not.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2136">RFC 2136: Dynamic Updates in the
   *     Domain Name System (DNS UPDATE)</a>
   */
  public static final int YXDOMAIN = 6;

  /**
   * RR Set Exists when it should not.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2136">RFC 2136: Dynamic Updates in the
   *     Domain Name System (DNS UPDATE)</a>
   */
  public static final int YXRRSET = 7;

  /**
   * The RR Set that should exist does not.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2136">RFC 2136: Dynamic Updates in the
   *     Domain Name System (DNS UPDATE)</a>
   */
  public static final int NXRRSET = 8;

  /**
   * Server Not Authoritative for zone (RFC 2136); Not Authorized (RFC 8945).
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2136">RFC 2136: Dynamic Updates in the
   *     Domain Name System (DNS UPDATE)</a>
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8945">RFC 8945: Secret Key Transaction
   *     Authentication for DNS (TSIG)</a>
   */
  public static final int NOTAUTH = 9;

  /**
   * Name not contained in zone.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2136">RFC 2136: Dynamic Updates in the
   *     Domain Name System (DNS UPDATE)</a>
   */
  public static final int NOTZONE = 10;

  /**
   * DSO-TYPE Not Implemented.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8490">RFC 8490: DNS Stateful
   *     Operations</a>
   * @since 3.7.0
   */
  public static final int DSOTYPENI = 11;

  /**
   * Bad OPT Version.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc6891">RFC 6891: Extension Mechanisms for
   *     DNS (EDNS(0))</a>
   */
  public static final int BADVERS = 16;

  /**
   * TSIG Signature Failure.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8945">RFC 8945: Secret Key Transaction
   *     Authentication for DNS (TSIG)</a>
   */
  public static final int BADSIG = 16;

  /**
   * Key not recognized.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8945">RFC 8945: Secret Key Transaction
   *     Authentication for DNS (TSIG)</a>
   */
  public static final int BADKEY = 17;

  /**
   * Signature out of time window.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8945">RFC 8945: Secret Key Transaction
   *     Authentication for DNS (TSIG)</a>
   */
  public static final int BADTIME = 18;

  /**
   * Bad TKEY Mode.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2930">RFC 2930: Secret Key Establishment
   *     for DNS (TKEY RR)</a>
   */
  public static final int BADMODE = 19;

  /**
   * Duplicate key name.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2930">RFC 2930: Secret Key Establishment
   *     for DNS (TKEY RR)</a>
   */
  public static final int BADNAME = 20;

  /**
   * Algorithm not supported.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc2930">RFC 2930: Secret Key Establishment
   *     for DNS (TKEY RR)</a>
   */
  public static final int BADALG = 21;

  /**
   * Bad Truncation.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8945">RFC 8945: Secret Key Transaction
   *     Authentication for DNS (TSIG)</a>
   */
  public static final int BADTRUNC = 22;

  /**
   * Bad/missing server cookie.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7873">RFC 7873: Domain Name System (DNS)
   *     Cookies</a>
   */
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
    rcodes.add(DSOTYPENI, "DSOTYPENI");
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

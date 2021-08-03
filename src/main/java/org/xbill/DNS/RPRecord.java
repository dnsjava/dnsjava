// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * Responsible Person Record - lists the mail address of a responsible person and a domain where TXT
 * records are available.
 *
 * @author Tom Scola (tscola@research.att.com)
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1183">RFC 1183: New DNS RR Definitions</a>
 */
public class RPRecord extends Record {
  private Name mailbox;
  private Name textDomain;

  RPRecord() {}

  /**
   * Creates an RP Record from the given data
   *
   * @param mailbox The responsible person
   * @param textDomain The address where TXT records can be found
   */
  public RPRecord(Name name, int dclass, long ttl, Name mailbox, Name textDomain) {
    super(name, Type.RP, dclass, ttl);

    this.mailbox = checkName("mailbox", mailbox);
    this.textDomain = checkName("textDomain", textDomain);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    mailbox = new Name(in);
    textDomain = new Name(in);
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    mailbox = st.getName(origin);
    textDomain = st.getName(origin);
  }

  /** Converts the RP Record to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(mailbox);
    sb.append(" ");
    sb.append(textDomain);
    return sb.toString();
  }

  /** Gets the mailbox address of the RP Record */
  public Name getMailbox() {
    return mailbox;
  }

  /** Gets the text domain info of the RP Record */
  public Name getTextDomain() {
    return textDomain;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    mailbox.toWire(out, null, canonical);
    textDomain.toWire(out, null, canonical);
  }
}

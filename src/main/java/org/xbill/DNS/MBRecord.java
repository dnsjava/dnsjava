// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Mailbox Record - specifies a host containing a mailbox.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc883">RFC 883: Domain Names - Implementation and
 *     Specification</a>
 */
public class MBRecord extends SingleNameBase {
  MBRecord() {}

  /**
   * Creates a new MB Record with the given data
   *
   * @param mailbox The host containing the mailbox for the domain.
   */
  public MBRecord(Name name, int dclass, long ttl, Name mailbox) {
    super(name, Type.MB, dclass, ttl, mailbox, "mailbox");
  }

  /** Gets the mailbox for the domain */
  public Name getMailbox() {
    return getSingleName();
  }

  @Override
  public Name getAdditionalName() {
    return getSingleName();
  }
}

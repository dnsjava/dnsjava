// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Mail Group Record - specifies a mailbox which is a member of a mail group.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc883">RFC 883: Domain Names - Implementation and
 *     Specification</a>
 */
public class MGRecord extends SingleNameBase {
  MGRecord() {}

  /**
   * Creates a new MG Record with the given data
   *
   * @param mailbox The mailbox that is a member of the group specified by the domain.
   */
  public MGRecord(Name name, int dclass, long ttl, Name mailbox) {
    super(name, Type.MG, dclass, ttl, mailbox, "mailbox");
  }

  /** Gets the mailbox in the mail group specified by the domain */
  public Name getMailbox() {
    return getSingleName();
  }
}

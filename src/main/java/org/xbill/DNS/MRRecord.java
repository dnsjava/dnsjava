// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Mailbox Rename Record - specifies a rename of a mailbox.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc883">RFC 883: Domain Names - Implementation and
 *     Specification</a>
 */
public class MRRecord extends SingleNameBase {
  MRRecord() {}

  /**
   * Creates a new MR Record with the given data
   *
   * @param newName The new name of the mailbox specified by the domain. domain.
   */
  public MRRecord(Name name, int dclass, long ttl, Name newName) {
    super(name, Type.MR, dclass, ttl, newName, "new name");
  }

  /** Gets the new name of the mailbox specified by the domain */
  public Name getNewName() {
    return getSingleName();
  }
}

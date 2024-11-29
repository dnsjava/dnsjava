// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * CNAME Record - maps an alias to its real name
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc1035">RFC 1035: Domain Names -
 *     Implementation and Specification</a>
 */
public class CNAMERecord extends SingleCompressedNameBase {
  CNAMERecord() {}

  /**
   * Creates a new CNAMERecord with the given data
   *
   * @param target The name to which the CNAME alias points
   */
  public CNAMERecord(Name name, int dclass, long ttl, Name target) {
    super(name, Type.CNAME, dclass, ttl, target, "target");
  }

  /** Gets the target of the CNAME Record */
  public Name getTarget() {
    return getSingleName();
  }

  /**
   * Gets the name of this record, aka the <i>alias</i> or <i>label</i> to the <i>canonical name</i>
   * specified in {@link #getTarget()}.
   *
   * @deprecated use {@link #getName()}
   */
  @Deprecated
  public Name getAlias() {
    return getName();
  }
}

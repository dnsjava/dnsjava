// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * CNAME Record - maps an alias to its real name
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class CNAMERecord extends SingleCompressedNameBase {
  CNAMERecord() {}

  /**
   * Creates a new CNAMERecord with the given data
   *
   * @param alias The name to which the CNAME alias points
   */
  public CNAMERecord(Name name, int dclass, long ttl, Name alias) {
    super(name, Type.CNAME, dclass, ttl, alias, "alias");
  }

  /** Gets the target of the CNAME Record */
  public Name getTarget() {
    return getSingleName();
  }

  /** Gets the alias specified by the CNAME Record */
  public Name getAlias() {
    return getSingleName();
  }
}

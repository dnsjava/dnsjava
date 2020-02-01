// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Name Server Record - contains the name server serving the named zone
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class NSRecord extends SingleCompressedNameBase {
  NSRecord() {}

  /**
   * Creates a new NS Record with the given data
   *
   * @param target The name server for the given domain
   */
  public NSRecord(Name name, int dclass, long ttl, Name target) {
    super(name, Type.NS, dclass, ttl, target, "target");
  }

  /** Gets the target of the NS Record */
  public Name getTarget() {
    return getSingleName();
  }

  @Override
  public Name getAdditionalName() {
    return getSingleName();
  }
}

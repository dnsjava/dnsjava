// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Key Exchange - delegation of authority
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc2230">RFC 2230: Key Exchange Delegation Record for
 *     the DNS</a>
 */
public class KXRecord extends U16NameBase {
  KXRecord() {}

  /**
   * Creates a KX Record from the given data
   *
   * @param preference The preference of this KX. Records with lower priority are preferred.
   * @param target The host that authority is delegated to
   */
  public KXRecord(Name name, int dclass, long ttl, int preference, Name target) {
    super(name, Type.KX, dclass, ttl, preference, "preference", target, "target");
  }

  /** Returns the target of the KX record */
  public Name getTarget() {
    return getNameField();
  }

  /** Returns the preference of this KX record */
  public int getPreference() {
    return getU16Field();
  }

  @Override
  public Name getAdditionalName() {
    return getNameField();
  }
}

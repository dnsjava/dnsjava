// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec;

import java.util.List;
import lombok.EqualsAndHashCode;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;

/**
 * An extended version of {@link RRset} that adds the indication of DNSSEC security status.
 *
 * @since 3.5
 */
@EqualsAndHashCode(
    callSuper = true,
    of = {"securityStatus", "ownerName"})
class SRRset extends RRset {
  private SecurityStatus securityStatus;
  private Name ownerName;

  /** Create a new, blank SRRset. */
  public SRRset() {
    super();
    this.securityStatus = SecurityStatus.UNCHECKED;
  }

  /**
   * Create a new SRRset with one record.
   *
   * @param r The record to add to the RRset.
   */
  public SRRset(Record r) {
    super(r);
    this.securityStatus = SecurityStatus.UNCHECKED;
  }

  /**
   * Create a new SRRset from an existing RRset. This SRRset will contain the same internal {@link
   * Record} objects as the original RRset.
   *
   * @param r The RRset to copy.
   */
  public SRRset(RRset r) {
    super(r);
    this.securityStatus = SecurityStatus.UNCHECKED;
  }

  /**
   * Create a new SRRset from an existing SRRset. This SRRset will contain the same internal {@link
   * Record} objects as the original SRRset.
   *
   * @param r The RRset to copy.
   */
  public SRRset(SRRset r) {
    super(r);
    this.securityStatus = r.securityStatus;
    this.ownerName = r.ownerName;
  }

  /**
   * Return the current security status (generally: {@link SecurityStatus#UNCHECKED}, {@link
   * SecurityStatus#BOGUS}, or {@link SecurityStatus#SECURE}).
   *
   * @return The security status for this set, {@link SecurityStatus#UNCHECKED} if it has never been
   *     set manually.
   */
  public SecurityStatus getSecurityStatus() {
    return this.securityStatus;
  }

  /**
   * Set the current security status for this SRRset.
   *
   * @param status The new security status for this set.
   */
  public void setSecurityStatus(SecurityStatus status) {
    this.securityStatus = status;
  }

  /** @return The "signer" name for this SRRset, if signed, or null if not. */
  public Name getSignerName() {
    List<RRSIGRecord> sigs = sigs();
    if (!sigs.isEmpty()) {
      return sigs.get(0).getSigner();
    }

    return null;
  }

  @Override
  public Name getName() {
    return this.ownerName == null ? super.getName() : this.ownerName;
  }

  /**
   * Set the name of the records.
   *
   * @param ownerName the {@link Name} to override the original name with.
   */
  public void setName(Name ownerName) {
    this.ownerName = ownerName;
  }
}

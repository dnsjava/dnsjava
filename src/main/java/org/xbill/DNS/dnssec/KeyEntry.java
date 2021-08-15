// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs

package org.xbill.DNS.dnssec;

import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * DNSKEY cache entry for a given {@link Name}, with or without actual keys.
 *
 * @since 3.5
 */
@Slf4j
@EqualsAndHashCode(
    callSuper = true,
    of = {"badReason", "isEmpty"})
final class KeyEntry extends SRRset {
  private String badReason;
  private boolean isEmpty;

  /**
   * Create a new, positive key entry.
   *
   * @param rrset The set of records to cache.
   */
  private KeyEntry(SRRset rrset) {
    super(rrset);
  }

  private KeyEntry(Name name, int dclass, long ttl, boolean isBad) {
    super(new SRRset(Record.newRecord(name, Type.DNSKEY, dclass, ttl)));
    this.isEmpty = true;
    if (isBad) {
      setSecurityStatus(SecurityStatus.BOGUS);
    }
  }

  /**
   * Creates a new key entry from actual DNSKEYs.
   *
   * @param rrset The DNSKEYs to cache.
   * @return The created key entry.
   */
  public static KeyEntry newKeyEntry(SRRset rrset) {
    return new KeyEntry(rrset);
  }

  /**
   * Creates a new trusted key entry without actual DNSKEYs, i.e. it is proven that there are no
   * keys.
   *
   * @param n The name for which the empty cache entry is created.
   * @param dclass The DNS class.
   * @param ttl The TTL [s].
   * @return The created key entry.
   */
  public static KeyEntry newNullKeyEntry(Name n, int dclass, long ttl) {
    return new KeyEntry(n, dclass, ttl, false);
  }

  /**
   * Creates a new bad key entry without actual DNSKEYs, i.e. from a response that did not validate.
   *
   * @param n The name for which the bad cache entry is created.
   * @param dclass The DNS class.
   * @param ttl The TTL [s].
   * @return The created key entry.s
   */
  public static KeyEntry newBadKeyEntry(Name n, int dclass, long ttl) {
    return new KeyEntry(n, dclass, ttl, true);
  }

  /**
   * Gets an indication if this is a null key, i.e. a proven secure response without keys.
   *
   * @return <code>True</code> is it is null, <code>false</code> otherwise.
   */
  public boolean isNull() {
    return this.isEmpty && this.getSecurityStatus() == SecurityStatus.UNCHECKED;
  }

  /**
   * Gets an indication if this is a bad key, i.e. an invalid response.
   *
   * @return <code>True</code> is it is bad, <code>false</code> otherwise.
   */
  public boolean isBad() {
    return this.isEmpty && this.getSecurityStatus() == SecurityStatus.BOGUS;
  }

  /**
   * Gets an indication if this is a good key, i.e. a proven secure response with keys.
   *
   * @return <code>True</code> is it is good, <code>false</code> otherwise.
   */
  public boolean isGood() {
    return !this.isEmpty && this.getSecurityStatus() == SecurityStatus.SECURE;
  }

  /**
   * Sets the reason why this key entry is bad.
   *
   * @param reason The reason why this key entry is bad.
   */
  public void setBadReason(String reason) {
    this.badReason = reason;
    log.debug(this.badReason);
  }

  /**
   * Validate if this key instance is valid for the specified name.
   *
   * @param signerName the name against which this key is validated.
   * @return A security status indicating if this key is valid, or if not, why.
   */
  JustifiedSecStatus validateKeyFor(Name signerName) {
    // signerName being null is the indicator that this response was
    // unsigned
    if (signerName == null) {
      log.debug("no signerName");
      // Unsigned responses must be underneath a "null" key entry.
      if (this.isNull()) {
        String reason = this.badReason;
        if (reason == null) {
          reason = R.get("validate.insecure_unsigned");
        }

        return new JustifiedSecStatus(SecurityStatus.INSECURE, reason);
      }

      if (this.isGood()) {
        return new JustifiedSecStatus(SecurityStatus.BOGUS, R.get("validate.bogus.missingsig"));
      }

      return new JustifiedSecStatus(SecurityStatus.BOGUS, R.get("validate.bogus", this.badReason));
    }

    if (this.isBad()) {
      return new JustifiedSecStatus(
          SecurityStatus.BOGUS, R.get("validate.bogus.badkey", this.getName(), this.badReason));
    }

    if (this.isNull()) {
      String reason = this.badReason;
      if (reason == null) {
        reason = R.get("validate.insecure");
      }

      return new JustifiedSecStatus(SecurityStatus.INSECURE, reason);
    }

    return null;
  }
}

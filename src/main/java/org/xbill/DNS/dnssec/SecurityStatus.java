// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package org.xbill.DNS.dnssec;

/**
 * Codes for DNSSEC security statuses.
 *
 * @since 3.5
 */
public enum SecurityStatus {
  /** UNCHECKED means that object has yet to be validated. */
  UNCHECKED,

  /**
   * BOGUS means that the object (RRset or message) failed to validate (according to local policy),
   * but should have validated.
   */
  BOGUS,

  /**
   * INDTERMINATE means that the object is insecure, but not authoritatively so. Generally this
   * means that the RRset is not below a configured trust anchor.
   */
  INDETERMINATE,

  /**
   * INSECURE means that the object is authoritatively known to be insecure. Generally this means
   * that this RRset is below a trust anchor, but also below a verified, insecure delegation.
   */
  INSECURE,

  /** SECURE means that the object (RRset or message) validated according to local policy. */
  SECURE,
}

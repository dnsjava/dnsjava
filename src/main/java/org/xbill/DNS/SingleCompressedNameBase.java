// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Implements common functionality for the many record types whose format is a single compressed
 * name.
 *
 * @author Brian Wellington
 */
abstract class SingleCompressedNameBase extends SingleNameBase {
  protected SingleCompressedNameBase() {}

  protected SingleCompressedNameBase(
      Name name, int type, int dclass, long ttl, Name singleName, String description) {
    super(name, type, dclass, ttl, singleName, description);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    singleName.toWire(out, c, canonical);
  }
}

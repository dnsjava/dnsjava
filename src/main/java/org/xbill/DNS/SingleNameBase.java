// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * Implements common functionality for the many record types whose format is a single name.
 *
 * @author Brian Wellington
 */
abstract class SingleNameBase extends Record {
  protected Name singleName;

  protected SingleNameBase() {}

  protected SingleNameBase(Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected SingleNameBase(
      Name name, int type, int dclass, long ttl, Name singleName, String description) {
    super(name, type, dclass, ttl);
    this.singleName = checkName(description, singleName);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    singleName = new Name(in);
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    singleName = st.getName(origin);
  }

  @Override
  protected String rrToString() {
    return singleName.toString();
  }

  protected Name getSingleName() {
    return singleName;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    singleName.toWire(out, null, canonical);
  }
}

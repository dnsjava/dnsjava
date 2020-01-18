// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * A class implementing Records with no data; that is, records used in the question section of
 * messages and meta-records in dynamic update.
 *
 * @author Brian Wellington
 */
class EmptyRecord extends Record {
  EmptyRecord() {}

  @Override
  Record getObject() {
    return new EmptyRecord();
  }

  @Override
  void rrFromWire(DNSInput in) {}

  @Override
  void rdataFromString(Tokenizer st, Name origin) {}

  @Override
  String rrToString() {
    return "";
  }

  @Override
  void rrToWire(DNSOutput out, Compression c, boolean canonical) {}
}

package org.xbill.DNS;

import java.util.Map;

public class SVCBRecord extends SVCBBase {
  SVCBRecord() {}

  public SVCBRecord(Name name, int dclass, long ttl, int priority, Name domain, Map<Integer, String> value) {
    super(name, Type.SVCB, dclass, ttl, priority, domain, value);
  }
}

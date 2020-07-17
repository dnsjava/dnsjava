package org.xbill.DNS;

import java.util.Map;

public class HTTPSRecord extends SVCBBase {
  HTTPSRecord() {}

  public HTTPSRecord(Name name, int dclass, long ttl, int priority, Name domain, Map<Integer, SVCBParameterBase> value) {
    super(name, Type.SVCB, dclass, ttl, priority, domain, value);
  }
}

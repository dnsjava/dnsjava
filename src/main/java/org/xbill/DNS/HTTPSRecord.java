package org.xbill.DNS;

import java.util.List;

public class HTTPSRecord extends SVCBBase {
  HTTPSRecord() {}

  public HTTPSRecord(Name name, int dclass, long ttl, int priority, Name domain, List<SVCBParameterBase> value) {
    super(name, Type.HTTPS, dclass, ttl, priority, domain, value);
  }
}

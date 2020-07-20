package org.xbill.DNS;

import java.util.List;

public class SVCBRecord extends SVCBBase {
  SVCBRecord() {}

  public SVCBRecord(Name name, int dclass, long ttl, int priority, Name domain, List<ParameterBase> params) {
    super(name, Type.SVCB, dclass, ttl, priority, domain, params);
  }
}

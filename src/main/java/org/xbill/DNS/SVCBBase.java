package org.xbill.DNS;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

abstract class SVCBBase extends Record {
  protected int svcFieldPriority;
  protected Name svcDomainName;
  protected Map<Integer, byte[]> svcFieldValue;

  protected static final int MANDATORY = 0;
  protected static final int ALPN = 1;
  protected static final int NO_DEFAULT_ALPN = 2;
  protected static final int PORT = 3;
  protected static final int IPV4HINT = 4;
  protected static final int ECHCONFIG = 5;
  protected static final int IPV6HINT = 6;

  protected static final Mnemonic parameters = new Mnemonic("SVCB/HTTPS Parameters", Mnemonic.CASE_LOWER);

  static {
    parameters.setMaximum(0xFFFF);
    parameters.add(MANDATORY, "mandatory");
    parameters.add(ALPN, "alpn");
    parameters.add(NO_DEFAULT_ALPN, "no-default-alpn");
    parameters.add(PORT, "port");
    parameters.add(IPV4HINT, "ipv4hint");
    parameters.add(ECHCONFIG, "echconfig");
    parameters.add(IPV6HINT, "ipv6hint");
  }

  protected SVCBBase() {}

  protected SVCBBase(Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected SVCBBase(Name name, int type, int dclass, long ttl, int priority, Name domain, Map<Integer, String> value) {
    super(name, type, dclass, ttl);
    svcFieldPriority = priority;
    this.svcFieldValue = new TreeMap<>();
    try {
      for (Integer i : value.keySet()) {
        this.svcFieldValue.put(i, byteArrayFromString(value.get(i)));
      }
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {

  }

  @Override
  protected String rrToString() {
    return null;
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {

  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {

  }
}

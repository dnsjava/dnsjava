package org.xbill.DNS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

abstract class SVCBBase extends Record {
  protected int svcFieldPriority;
  protected Name svcDomainName;
  protected Map<Integer, SVCBParameterBase> svcFieldValue;

  protected static final int MANDATORY = 0;
  protected static final int ALPN = 1;
  protected static final int NO_DEFAULT_ALPN = 2;
  protected static final int PORT = 3;
  protected static final int IPV4HINT = 4;
  protected static final int ECHCONFIG = 5;
  protected static final int IPV6HINT = 6;

  protected SVCBBase() {}

  protected SVCBBase(Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected SVCBBase(Name name, int type, int dclass, long ttl, int priority, Name domain, Map<Integer, SVCBParameterBase> value) {
    super(name, type, dclass, ttl);
    svcFieldPriority = priority;
    this.svcFieldValue = new TreeMap<>();
    for (Integer i : value.keySet()) {
      this.svcFieldValue.put(i, value.get(i));
    }
  }

  private static class ParameterMnemonic extends Mnemonic {
    private HashMap<Integer, Supplier<SVCBParameterBase>> factories;

    public ParameterMnemonic() {
      super("SVCB/HTTPS Parameters", Mnemonic.CASE_LOWER);
      setPrefix("key");
      setNumericAllowed(true);
      setMaximum(0xFFFF);
      factories = new HashMap<>();
    }

    public void add(int val, String str, Supplier<SVCBParameterBase> factory) {
      super.add(val, str);
      factories.put(val, factory);
    }

    public Supplier<SVCBParameterBase> getFactory(int val) {
      return factories.get(val);
    }
  }

  private static final ParameterMnemonic parameters = new ParameterMnemonic();

  static {
    parameters.add(MANDATORY, "mandatory", SVCBParameterMandatory::new);
    parameters.add(ALPN, "alpn", SVCBParameterAlpn::new);
    parameters.add(NO_DEFAULT_ALPN, "no-default-alpn", SVCBParameterNoDefaultAlpn::new);
    parameters.add(PORT, "port", SVCBParameterPort::new);
    parameters.add(IPV4HINT, "ipv4hint", SVCBParameterIpv4Hint::new);
    parameters.add(ECHCONFIG, "echconfig", SVCBParameterEchConfig::new);
    parameters.add(IPV6HINT, "ipv6hint", SVCBParameterIpv6Hint::new);
  }

  static abstract class SVCBParameterBase {
    public SVCBParameterBase() {}
    public abstract void fromWire(byte[] bytes) throws IOException;
    public abstract void fromString(String string) throws IOException;
    public abstract byte[] toWire();
    public abstract String toString();

    // Split on string on commas but not if comma is escaped with a '\'
    public static String[] splitStringWithEscapedCommas(String string) {
      return string.split("(?<!\\\\),");
    }
  }

  static private class SVCBParameterMandatory extends SVCBParameterBase {
    private List<Integer> values;

    public SVCBParameterMandatory() {
      super();
      values = new ArrayList<>();
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        int key = in.readU16();
        values.add(key);
      }
    }

    @Override
    public void fromString(String string) throws IOException {
      for (String str : splitStringWithEscapedCommas(string)) {
        int key = parameters.getValue(str);
        values.add(key);
      }
    }

    @Override
    public byte[] toWire() {
      DNSOutput out = new DNSOutput();
      for (Integer val : values) {
        out.writeU16(val);
      }
      return out.toByteArray();
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      for (Integer val : values) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(parameters.getText(val));
      }
      return sb.toString();
    }
  }

  static private class SVCBParameterAlpn extends SVCBParameterBase {
    private List<byte[]> values;

    public SVCBParameterAlpn() {
      super();
      values = new ArrayList<>();
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        byte[] b = in.readCountedString();
        values.add(b);
      }
    }

    @Override
    public void fromString(String string) throws IOException {
      for (String str : splitStringWithEscapedCommas(string)) {
        values.add(str.getBytes());
      }
    }

    @Override
    public byte[] toWire() {
      DNSOutput out = new DNSOutput();
      for (byte[] b : values) {
        out.writeCountedString(b);
      }
      return out.toByteArray();
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      for (byte[] b : values) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(new String(b));
      }
      return sb.toString();
    }
  }

  static private class SVCBParameterNoDefaultAlpn extends SVCBParameterBase {
    public SVCBParameterNoDefaultAlpn() { super(); }

    @Override
    public void fromWire(byte[] bytes) { }

    @Override
    public void fromString(String string) { }

    @Override
    public byte[] toWire() {
      return new byte[0];
    }

    @Override
    public String toString() {
      return new String();
    }
  }

  static private class SVCBParameterPort extends SVCBParameterBase {
    private int port;

    public SVCBParameterPort() { super(); }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      port = in.readU16();
    }

    @Override
    public void fromString(String string) {
      port = Integer.parseInt(string);
    }

    @Override
    public byte[] toWire() {
      DNSOutput out = new DNSOutput();
      out.writeU16(port);
      return out.toByteArray();
    }

    @Override
    public String toString() {
      return Integer.toString(port);
    }
  }

  static private class SVCBParameterIpv4Hint extends SVCBParameterBase {
    private List<byte[]> addresses;

    public SVCBParameterIpv4Hint() {
      super();
      addresses = new ArrayList<>();
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        addresses.add(in.readByteArray(4));
      }
    }

    @Override
    public void fromString(String string) {
      for (String str : string.split(",")) {
        byte[] address = Address.toByteArray(str, Address.IPv4);
        addresses.add(address);
      }
    }

    @Override
    public byte[] toWire() {
      DNSOutput out = new DNSOutput();
      for (byte[] b : addresses) {
        out.writeByteArray(b);
      }
      return out.toByteArray();
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      for (byte[] b : addresses) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        sb.append(Address.toDottedQuad(b));
      }
      return sb.toString();
    }
  }

  static private class SVCBParameterEchConfig extends SVCBParameterBase {
    private byte[] data;

    public SVCBParameterEchConfig() { super(); }

    @Override
    public void fromWire(byte[] bytes) {
      data = bytes;
    }

    @Override
    public void fromString(String string) {
      data = Base64.getDecoder().decode(string);
    }

    @Override
    public byte[] toWire() {
      return data;
    }

    @Override
    public String toString() {
      return Base64.getEncoder().encodeToString(data);
    }
  }

  static private class SVCBParameterIpv6Hint extends SVCBParameterBase {
    private List<byte[]> addresses;

    public SVCBParameterIpv6Hint() {
      super();
      addresses = new ArrayList<>();
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        addresses.add(in.readByteArray(16));
      }
    }

    @Override
    public void fromString(String string) {
      for (String str : string.split(",")) {
        byte[] address = Address.toByteArray(str, Address.IPv6);
        addresses.add(address);
      }
    }

    @Override
    public byte[] toWire() {
      DNSOutput out = new DNSOutput();
      for (byte[] b : addresses) {
        out.writeByteArray(b);
      }
      return out.toByteArray();
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      for (byte[] b : addresses) {
        if (sb.length() > 0) {
          sb.append(",");
        }
        try {
          InetAddress addr = InetAddress.getByAddress(null, b);
          sb.append(addr.getCanonicalHostName());
        } catch (UnknownHostException e) {
          return null;
        }
      }
      return sb.toString();
    }
  }

  static private class SVCBParameterUnknown extends SVCBParameterBase {
    public SVCBParameterUnknown() { super(); }

    @Override
    public void fromWire(byte[] bytes) {

    }

    @Override
    public void fromString(String string) {

    }

    @Override
    public byte[] toWire() {
      return new byte[0];
    }

    @Override
    public String toString() {
      return null;
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    svcFieldPriority = in.readU16();
    svcDomainName = new Name(in);
    svcFieldValue = new TreeMap<>();
    while (in.remaining() > 0) {
      int key = in.readU16();
      int length = in.readU16();
      byte[] value = in.readByteArray(length);
      SVCBParameterBase param;
      Supplier<SVCBParameterBase> factory = parameters.getFactory(key);
      if (factory != null) {
        param = factory.get();
      } else {
        param = new SVCBParameterUnknown();
      }
      param.fromWire(value);
      svcFieldValue.put(key, param);
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(svcFieldPriority);
    sb.append(" ");
    sb.append(svcDomainName);
    for (Integer key : svcFieldValue.keySet()) {
      sb.append(" ");
      sb.append(parameters.getText(key));
      SVCBParameterBase param = svcFieldValue.get(key);
      String value = param.toString();
      if (value != null && !value.isEmpty()) {
        sb.append("=");
        sb.append(value);
      }
    }
    return sb.toString();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    svcFieldPriority = st.getUInt16();
    svcDomainName = st.getName(origin);
    svcFieldValue = new TreeMap<>();
    while (true) {
      String keyStr = null;
      String valueStr = null;
      Tokenizer.Token t = st.get();
      System.out.println("AWS token: " + t);
      if (!t.isString()) {
        break;
      }
      int indexOfEquals = t.value.indexOf('=');
      if (indexOfEquals == -1) {
        // No "=" is key with no value case, set the value as empty byte sequence
        keyStr = t.value;
      }
      else if (indexOfEquals == t.value.length() - 1) {
        // Ends with "=" means the next token is quoted string with the value
        keyStr = t.value.substring(0, indexOfEquals);
        t = st.get();
        if (!t.isString()) {
          // ERROR
        }
        valueStr = t.value;
      }
      else if (indexOfEquals > 0 ) {
        // If "=" is in the middle then need to split the key and value from this token
        keyStr = t.value.substring(0, indexOfEquals);
        valueStr = t.value.substring(indexOfEquals + 1);
      }
      else {
        // If "=" is the first character it is invalid since key must be specified
      }

      SVCBParameterBase param;
      int key = parameters.getValue(keyStr);
      Supplier<SVCBParameterBase> factory = parameters.getFactory(key);
      if (factory != null) {
        param = factory.get();
      } else {
        param = new SVCBParameterUnknown();
      }
      param.fromString(valueStr);
      svcFieldValue.put(key, param);
    }
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(svcFieldPriority);
    svcDomainName.toWire(out, null, canonical);
    for (Integer key : svcFieldValue.keySet()) {
      out.writeU16(key);
      SVCBParameterBase param = svcFieldValue.get(key);
      byte[] value = param.toWire();
      out.writeU16(value.length);
      out.writeByteArray(value);
    }
  }
}

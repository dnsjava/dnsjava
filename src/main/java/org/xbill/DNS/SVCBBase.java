package org.xbill.DNS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;

abstract class SVCBBase extends Record {
  protected int svcPriority;
  protected Name targetName;
  protected Map<Integer, ParameterBase> svcParams;

  public static final int MANDATORY = 0;
  public static final int ALPN = 1;
  public static final int NO_DEFAULT_ALPN = 2;
  public static final int PORT = 3;
  public static final int IPV4HINT = 4;
  public static final int ECHCONFIG = 5;
  public static final int IPV6HINT = 6;

  protected SVCBBase() {}

  protected SVCBBase(Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected SVCBBase(Name name, int type, int dclass, long ttl, int priority, Name domain, List<ParameterBase> params) {
    super(name, type, dclass, ttl);
    svcPriority = priority;
    targetName = domain;
    this.svcParams = new TreeMap<>();
    for (ParameterBase param : params) {
      this.svcParams.put(param.getKey(), param);
    }
  }

  public int getSvcPriority() {
    return svcPriority;
  }

  public Name getTargetName() {
    return targetName;
  }

  public Set<Integer> getSvcParamKeys() {
    return svcParams.keySet();
  }

  public ParameterBase getSvcParamValue(int key) {
    return svcParams.get(key);
  }

  private static class ParameterMnemonic extends Mnemonic {
    private HashMap<Integer, Supplier<ParameterBase>> factories;

    public ParameterMnemonic() {
      super("SVCB/HTTPS Parameters", Mnemonic.CASE_LOWER);
      setPrefix("key");
      setNumericAllowed(true);
      setMaximum(0xFFFF);
      factories = new HashMap<>();
    }

    public void add(int val, String str, Supplier<ParameterBase> factory) {
      super.add(val, str);
      factories.put(val, factory);
    }

    public Supplier<ParameterBase> getFactory(int val) {
      return factories.get(val);
    }
  }

  private static final ParameterMnemonic parameters = new ParameterMnemonic();

  static {
    parameters.add(MANDATORY, "mandatory", ParameterMandatory::new);
    parameters.add(ALPN, "alpn", ParameterAlpn::new);
    parameters.add(NO_DEFAULT_ALPN, "no-default-alpn", ParameterNoDefaultAlpn::new);
    parameters.add(PORT, "port", ParameterPort::new);
    parameters.add(IPV4HINT, "ipv4hint", ParameterIpv4Hint::new);
    parameters.add(ECHCONFIG, "echconfig", ParameterEchConfig::new);
    parameters.add(IPV6HINT, "ipv6hint", ParameterIpv6Hint::new);
  }

  static public abstract class ParameterBase {
    public ParameterBase() {}
    public abstract int getKey();
    public abstract void fromWire(byte[] bytes) throws IOException;
    public abstract void fromString(String string) throws IOException;
    public abstract byte[] toWire();
    public abstract String toString();

    // Split on string on commas but not if comma is escaped with a '\'
    public static String[] splitStringWithEscapedCommas(String string) {
      return string.split("(?<!\\\\),");
    }
  }

  static public class ParameterMandatory extends ParameterBase {
    private List<Integer> values;

    public ParameterMandatory() {
      super();
      values = new ArrayList<>();
    }

    @Override
    public int getKey() {
      return MANDATORY;
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
    public void fromString(String string) {
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

  static public class ParameterAlpn extends ParameterBase {
    private List<byte[]> values;

    public ParameterAlpn() {
      super();
      values = new ArrayList<>();
    }

    @Override
    public int getKey() {
      return ALPN;
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
    public void fromString(String string) {
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

  static public class ParameterNoDefaultAlpn extends ParameterBase {
    public ParameterNoDefaultAlpn() { super(); }

    @Override
    public int getKey() {
      return NO_DEFAULT_ALPN;
    }

    @Override
    public void fromWire(byte[] bytes) { }

    @Override
    public void fromString(String string) throws TextParseException {
      if (string != null && !string.isEmpty()) {
        throw new TextParseException("No value can be specified for no-default-alpn");
      }
    }

    @Override
    public byte[] toWire() {
      return new byte[0];
    }

    @Override
    public String toString() {
      return "";
    }
  }

  static public class ParameterPort extends ParameterBase {
    private int port;

    public ParameterPort() { super(); }

    @Override
    public int getKey() {
      return PORT;
    }

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

  static public class ParameterIpv4Hint extends ParameterBase {
    private List<byte[]> addresses;

    public ParameterIpv4Hint() {
      super();
      addresses = new ArrayList<>();
    }

    @Override
    public int getKey() {
      return IPV4HINT;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        addresses.add(in.readByteArray(4));
      }
    }

    @Override
    public void fromString(String string) throws IOException {
      for (String str : string.split(",")) {
        byte[] address = Address.toByteArray(str, Address.IPv4);
        if (address == null) {
          throw new TextParseException("Invalid ipv4hint value '" + string + "'");
        }
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

  static public class ParameterEchConfig extends ParameterBase {
    private byte[] data;

    public ParameterEchConfig() { super(); }

    @Override
    public int getKey() {
      return ECHCONFIG;
    }

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

  static public class ParameterIpv6Hint extends ParameterBase {
    private List<byte[]> addresses;

    public ParameterIpv6Hint() {
      super();
      addresses = new ArrayList<>();
    }

    @Override
    public int getKey() {
      return IPV6HINT;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        addresses.add(in.readByteArray(16));
      }
    }

    @Override
    public void fromString(String string) throws IOException {
      for (String str : string.split(",")) {
        byte[] address = Address.toByteArray(str, Address.IPv6);
        if (address == null) {
          throw new TextParseException("Invalid ipv6hint value '" + string + "'");
        }
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

  static public class ParameterUnknown extends ParameterBase {
    private int key;
    private byte[] value;

    public ParameterUnknown(int key) {
      super();
      this.key = key;
    }

    @Override
    public int getKey() {
      return key;
    }

    @Override
    public void fromWire(byte[] bytes) {
      value = bytes;
    }

    @Override
    public void fromString(String string) throws IOException {
      value =  byteArrayFromString(string);
    }

    @Override
    public byte[] toWire() {
      return value;
    }

    @Override
    public String toString() {
      return byteArrayToString(value, false);
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    svcPriority = in.readU16();
    targetName = new Name(in);
    svcParams = new TreeMap<>();
    while (in.remaining() > 0) {
      int key = in.readU16();
      int length = in.readU16();
      byte[] value = in.readByteArray(length);
      ParameterBase param;
      Supplier<ParameterBase> factory = parameters.getFactory(key);
      if (factory != null) {
        param = factory.get();
      } else {
        param = new ParameterUnknown(key);
      }
      param.fromWire(value);
      svcParams.put(key, param);
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(svcPriority);
    sb.append(" ");
    sb.append(targetName);
    for (Integer key : svcParams.keySet()) {
      sb.append(" ");
      sb.append(parameters.getText(key));
      ParameterBase param = svcParams.get(key);
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
    svcPriority = st.getUInt16();
    targetName = st.getName(origin);
    svcParams = new TreeMap<>();
    while (true) {
      String keyStr = null;
      String valueStr = null;
      Tokenizer.Token t = st.get();
      if (!t.isString()) {
        break;
      }
      int indexOfEquals = t.value.indexOf('=');
      if (indexOfEquals == -1) {
        // No "=" is key with no value case, leave value string as null
        keyStr = t.value;
      }
      else if (indexOfEquals == t.value.length() - 1) {
        // Ends with "=" means the next token is quoted string with the value
        keyStr = t.value.substring(0, indexOfEquals);
        t = st.get();
        if (!t.isString()) {
          throw new TextParseException("Expected value for parameter key '" + keyStr + "'");
        }
        valueStr = t.value;
      }
      else if (indexOfEquals > 0 ) {
        // If "=" is in the middle then need to split the key and value from this token
        keyStr = t.value.substring(0, indexOfEquals);
        valueStr = t.value.substring(indexOfEquals + 1);
      }

      ParameterBase param;
      int key = parameters.getValue(keyStr);
      if (key == -1) {
        throw new TextParseException("Expected a valid parameter key for '" + keyStr + "'");
      }
      if (svcParams.containsKey(key)) {
        throw new TextParseException("Duplicate parameter key for '" + keyStr + "'");
      }
      Supplier<ParameterBase> factory = parameters.getFactory(key);
      if (factory != null) {
        param = factory.get();
      } else {
        param = new ParameterUnknown(key);
      }
      param.fromString(valueStr);
      svcParams.put(key, param);
    }

    if (svcPriority > 0 && svcParams.isEmpty()) {
      throw new TextParseException("At least one parameter value must be specified for ServiceMode");
    }
    if (svcPriority == 0 && !svcParams.isEmpty()) {
      throw new TextParseException("No parameter values allowed for AliasMode");
    }
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(svcPriority);
    targetName.toWire(out, null, canonical);
    for (Integer key : svcParams.keySet()) {
      out.writeU16(key);
      ParameterBase param = svcParams.get(key);
      byte[] value = param.toWire();
      out.writeU16(value.length);
      out.writeByteArray(value);
    }
  }
}

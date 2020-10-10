// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/** Implements common functionality for SVCB and HTTPS records */
abstract class SVCBBase extends Record {
  protected int svcPriority;
  protected Name targetName;
  protected final Map<Integer, ParameterBase> svcParams;

  public static final int MANDATORY = 0;
  public static final int ALPN = 1;
  public static final int NO_DEFAULT_ALPN = 2;
  public static final int PORT = 3;
  public static final int IPV4HINT = 4;
  public static final int ECHCONFIG = 5;
  public static final int IPV6HINT = 6;

  protected SVCBBase() {
    svcParams = new TreeMap<>();
  }

  protected SVCBBase(Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
    svcParams = new TreeMap<>();
  }

  protected SVCBBase(
      Name name,
      int type,
      int dclass,
      long ttl,
      int priority,
      Name domain,
      List<ParameterBase> params) {
    super(name, type, dclass, ttl);
    svcPriority = priority;
    targetName = domain;
    svcParams = new TreeMap<>();
    for (ParameterBase param : params) {
      if (svcParams.containsKey(param.getKey())) {
        throw new IllegalArgumentException("Duplicate SvcParam for key " + param.getKey());
      }
      svcParams.put(param.getKey(), param);
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

  public abstract static class ParameterBase {
    public ParameterBase() {}

    public abstract int getKey();

    public abstract void fromWire(byte[] bytes) throws IOException;

    public abstract void fromString(String string) throws IOException;

    public abstract byte[] toWire();

    public abstract String toString();

    // Split string on commas, but not if comma is escaped with a '\'
    public static String[] splitStringWithEscapedCommas(String string) {
      return string.split("(?<!\\\\),");
    }
  }

  public static class ParameterMandatory extends ParameterBase {
    private final List<Integer> values;

    public ParameterMandatory() {
      super();
      values = new ArrayList<>();
    }

    public ParameterMandatory(List<Integer> values) {
      super();
      this.values = values;
    }

    public List<Integer> getValues() {
      return values;
    }

    @Override
    public int getKey() {
      return MANDATORY;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      values.clear();
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() >= 2) {
        int key = in.readU16();
        values.add(key);
      }
      if (in.remaining() > 0) {
        throw new WireParseException("Unexpected number of bytes in mandatory parameter");
      }
    }

    @Override
    public void fromString(String string) throws TextParseException {
      values.clear();
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty list must be specified for mandatory");
      }
      for (String str : splitStringWithEscapedCommas(string)) {
        int key = parameters.getValue(str);
        if (key == MANDATORY) {
          throw new TextParseException("Key mandatory must not appear in its own list");
        }
        if (values.contains(key)) {
          throw new TextParseException("Duplicate key " + str + " not allowed in mandatory list");
        }
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

  public static class ParameterAlpn extends ParameterBase {
    private final List<byte[]> values;

    public ParameterAlpn() {
      super();
      values = new ArrayList<>();
    }

    public ParameterAlpn(List<String> values) throws TextParseException {
      super();
      this.values = new ArrayList<>();
      for (String str : values) {
        this.values.add(byteArrayFromString(str));
      }
    }

    public List<String> getValues() {
      List<String> values = new ArrayList<>();
      for (byte[] b : this.values) {
        values.add(byteArrayToString(b, false));
      }
      return values;
    }

    @Override
    public int getKey() {
      return ALPN;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      values.clear();
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() > 0) {
        byte[] b = in.readCountedString();
        values.add(b);
      }
    }

    @Override
    public void fromString(String string) throws TextParseException {
      values.clear();
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty list must be specified for alpn");
      }
      for (String str : splitStringWithEscapedCommas(string)) {
        values.add(byteArrayFromString(str));
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
        String str = byteArrayToString(b, false);
        str = str.replaceAll(",", "\\\\,");
        sb.append(str);
      }
      return sb.toString();
    }
  }

  public static class ParameterNoDefaultAlpn extends ParameterBase {
    public ParameterNoDefaultAlpn() {
      super();
    }

    @Override
    public int getKey() {
      return NO_DEFAULT_ALPN;
    }

    @Override
    public void fromWire(byte[] bytes) throws WireParseException {
      if (bytes.length > 0) {
        throw new WireParseException("No value can be specified for no-default-alpn");
      }
    }

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

  public static class ParameterPort extends ParameterBase {
    private int port;

    public ParameterPort() {
      super();
    }

    public ParameterPort(int port) {
      super();
      this.port = port;
    }

    public int getPort() {
      return port;
    }

    @Override
    public int getKey() {
      return PORT;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      DNSInput in = new DNSInput(bytes);
      port = in.readU16();
      if (in.remaining() > 0) {
        throw new WireParseException("Unexpected number of bytes in port parameter");
      }
    }

    @Override
    public void fromString(String string) throws TextParseException {
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Integer value must be specified for port");
      }
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

  public static class ParameterIpv4Hint extends ParameterBase {
    private final List<byte[]> addresses;

    public ParameterIpv4Hint() {
      super();
      addresses = new ArrayList<>();
    }

    public ParameterIpv4Hint(List<Inet4Address> addresses) {
      super();
      this.addresses =
          addresses.stream().map(Inet4Address::getAddress).collect(Collectors.toList());
    }

    public List<Inet4Address> getAddresses() throws UnknownHostException {
      List<Inet4Address> addresses = new LinkedList<>();
      for (byte[] bytes : this.addresses) {
        InetAddress address = InetAddress.getByAddress(bytes);
        if (address instanceof Inet4Address) {
          addresses.add((Inet4Address) address);
        }
      }
      return addresses;
    }

    @Override
    public int getKey() {
      return IPV4HINT;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      addresses.clear();
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() >= 4) {
        addresses.add(in.readByteArray(4));
      }
      if (in.remaining() > 0) {
        throw new WireParseException("Unexpected number of bytes in ipv4hint parameter");
      }
    }

    @Override
    public void fromString(String string) throws IOException {
      addresses.clear();
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty IPv4 list must be specified for ipv4hint");
      }
      for (String str : string.split(",")) {
        byte[] address = Address.toByteArray(str, Address.IPv4);
        if (address == null) {
          throw new TextParseException("Invalid ipv4hint value '" + str + "'");
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

  public static class ParameterEchConfig extends ParameterBase {
    private byte[] data;

    public ParameterEchConfig() {
      super();
    }

    public ParameterEchConfig(byte[] data) {
      super();
      this.data = data;
    }

    public byte[] getData() {
      return data;
    }

    @Override
    public int getKey() {
      return ECHCONFIG;
    }

    @Override
    public void fromWire(byte[] bytes) {
      data = bytes;
    }

    @Override
    public void fromString(String string) throws TextParseException {
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty base64 value must be specified for echconfig");
      }
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

  public static class ParameterIpv6Hint extends ParameterBase {
    private final List<byte[]> addresses;

    public ParameterIpv6Hint() {
      super();
      addresses = new ArrayList<>();
    }

    public ParameterIpv6Hint(List<Inet6Address> addresses) {
      super();
      this.addresses =
          addresses.stream().map(Inet6Address::getAddress).collect(Collectors.toList());
    }

    public List<Inet6Address> getAddresses() throws UnknownHostException {
      List<Inet6Address> addresses = new LinkedList<>();
      for (byte[] bytes : this.addresses) {
        InetAddress address = InetAddress.getByAddress(bytes);
        if (address instanceof Inet6Address) {
          addresses.add((Inet6Address) address);
        }
      }
      return addresses;
    }

    @Override
    public int getKey() {
      return IPV6HINT;
    }

    @Override
    public void fromWire(byte[] bytes) throws IOException {
      addresses.clear();
      DNSInput in = new DNSInput(bytes);
      while (in.remaining() >= 16) {
        addresses.add(in.readByteArray(16));
      }
      if (in.remaining() > 0) {
        throw new WireParseException("Unexpected number of bytes in ipv6hint parameter");
      }
    }

    @Override
    public void fromString(String string) throws IOException {
      addresses.clear();
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty IPv6 list must be specified for ipv6hint");
      }
      for (String str : string.split(",")) {
        byte[] address = Address.toByteArray(str, Address.IPv6);
        if (address == null) {
          throw new TextParseException("Invalid ipv6hint value '" + str + "'");
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

  public static class ParameterUnknown extends ParameterBase {
    private int key;
    private byte[] value;

    public ParameterUnknown(int key) {
      super();
      this.key = key;
      this.value = new byte[0];
    }

    public ParameterUnknown(int key, byte[] value) {
      super();
      this.key = key;
      this.value = value;
    }

    public byte[] getValue() {
      return value;
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
      if (string == null || string.isEmpty()) {
        value = new byte[0];
      } else {
        value = byteArrayFromString(string);
      }
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

  protected boolean checkMandatoryParams() {
    ParameterMandatory param = (ParameterMandatory) getSvcParamValue(MANDATORY);
    if (param != null) {
      for (int key : param.values) {
        if (getSvcParamValue(key) == null) {
          return false;
        }
      }
    }
    return true;
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    svcPriority = in.readU16();
    targetName = new Name(in);
    svcParams.clear();
    while (in.remaining() >= 4) {
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
    if (in.remaining() > 0) {
      throw new WireParseException("Record had unexpected number of bytes");
    }
    if (!checkMandatoryParams()) {
      throw new WireParseException("Not all mandatory SvcParams are specified");
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
    svcParams.clear();
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
      } else if (indexOfEquals == t.value.length() - 1) {
        // Ends with "=" means the next token is quoted string with the value
        keyStr = t.value.substring(0, indexOfEquals);
        Tokenizer.Token valueToken = st.get();
        if (!valueToken.isString()) {
          throw new TextParseException("Expected value for parameter key '" + keyStr + "'");
        }
        valueStr = valueToken.value;
      } else if (indexOfEquals > 0) {
        // If "=" is in the middle then need to split the key and value from this token
        keyStr = t.value.substring(0, indexOfEquals);
        valueStr = t.value.substring(indexOfEquals + 1);
      } else {
        throw new TextParseException("Expected valid parameter key=value for '" + t.value + "'");
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
    st.unget();

    if (svcPriority > 0 && svcParams.isEmpty()) {
      throw new TextParseException(
          "At least one parameter value must be specified for ServiceMode");
    }
    if (svcPriority == 0 && !svcParams.isEmpty()) {
      throw new TextParseException("No parameter values allowed for AliasMode");
    }
    if (!checkMandatoryParams()) {
      throw new TextParseException("Not all mandatory SvcParams are specified");
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

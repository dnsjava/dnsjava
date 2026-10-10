// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.io.Serializable;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.xbill.DNS.utils.base64;

/**
 * Implements common functionality for SVCB and HTTPS records
 *
 * @since 3.3
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9460">RFC 9460</a>
 */
public abstract class SVCBBase extends Record {
  protected int svcPriority;
  protected Name targetName;
  protected final Map<Integer, ParameterBase> svcParams;

  /**
   * Mandatory keys in this RR.
   *
   * @see <a href="https://www.rfc-editor.org/info/rfc9460/#section-8">RFC 9460, Section 8</a>
   */
  public static final int MANDATORY = 0;

  /**
   * Additional supported protocols.
   *
   * @see <a href="https://www.rfc-editor.org/info/rfc9460/#section-7.1">RFC 9460, Section 7.1</a>
   */
  public static final int ALPN = 1;

  /**
   * No support for default protocol.
   *
   * @see <a href="https://www.rfc-editor.org/info/rfc9460/#section-7.1">RFC 9460, Section 7.1</a>
   */
  public static final int NO_DEFAULT_ALPN = 2;

  /**
   * Port for alternative endpoint.
   *
   * @see <a href="https://www.rfc-editor.org/info/rfc9460/#section-7.2">RFC 9460, Section 7.2</a>
   */
  public static final int PORT = 3;

  /**
   * IPv4 address hints.
   *
   * @see <a href="https://www.rfc-editor.org/info/rfc9460/#section-7.3">RFC 9460, Section 7.3</a>
   */
  public static final int IPV4HINT = 4;

  /**
   * TLS Encrypted ClientHello Config.
   *
   * @since 3.4.1
   * @see <a href="https://www.iana.org/go/rfc9848">RFC 9848</a>
   */
  public static final int ECH = 5;

  /**
   * IPv6 address hints.
   *
   * @see <a href="https://www.rfc-editor.org/info/rfc9460/#section-7.3">RFC 9460, Section 7.3</a>
   */
  public static final int IPV6HINT = 6;

  /**
   * DNS over HTTPS path template.
   *
   * @since 3.6.6
   * @see <a href="https://www.iana.org/go/rfc9461">RFC 9461</a>
   */
  public static final int DOHPATH = 7;

  /**
   * Denotes that a service operates an Oblivious HTTP target.
   *
   * @since 3.6.6
   * @see <a href="https://www.rfc-editor.org/info/rfc9540/#section-4.2">RFC 9540, Section 4.2</a>
   */
  public static final int OHTTP = 8;

  /**
   * Supported groups in TLS.
   *
   * @since 3.6.6
   * @see <a
   *     href="https://datatracker.ietf.org/doc/html/draft-ietf-tls-key-share-prediction-04#name-format">draft-ietf-tls-key-share-prediction-04,
   *     Section 3.1</a>
   */
  public static final int TLS_SUPPORTED_GROUPS = 9;

  /**
   * DNS over CoAP resource path.
   *
   * @since 3.6.6
   * @see <a href="https://www.rfc-editor.org/info/rfc9953/#section-3">RFC 9953, Section 3.1</a>
   */
  public static final int DOCPATH = 10;

  /**
   * PvD configuration is available at the well-known path.
   *
   * @since 3.6.6
   * @see <a
   *     href="https://datatracker.ietf.org/doc/html/draft-ietf-intarea-proxy-config-14#section-2.1">RFC-ietf-intarea-proxy-config-14,
   *     Section 2.1</a>
   */
  public static final int PVD = 11;

  /**
   * Per-transport operator confidence in serving the nameserver's query load over that transport,
   * as a percentage.
   *
   * @since 3.6.6
   * @see <a
   *     href="https://datatracker.ietf.org/doc/html/draft-johani-dnsop-svcb-oots-00/#section-5">draft-johani-dnsop-svcb-oots-00,
   *     Section 5</a>
   */
  public static final int OOTS = 11;

  /**
   * Pre-RFC constant for the {@link #ECH} SVC parameter.
   *
   * @deprecated use {@link #ECH}
   */
  @Deprecated public static final int ECHCONFIG = ECH;

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
    private final HashMap<Integer, Supplier<ParameterBase>> factories;

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
    parameters.add(ECH, "ech", ParameterEch::new);
    parameters.add(IPV6HINT, "ipv6hint", ParameterIpv6Hint::new);
    parameters.add(DOHPATH, "dohpath", () -> new ParameterUnknown(DOHPATH));
    parameters.add(OHTTP, "ohttp", () -> new ParameterUnknown(OHTTP));
    parameters.add(
        TLS_SUPPORTED_GROUPS,
        "tls-supported-groups",
        () -> new ParameterUnknown(TLS_SUPPORTED_GROUPS));
    parameters.add(DOCPATH, "docpath", () -> new ParameterUnknown(DOCPATH));
    parameters.add(PVD, "pvd", () -> new ParameterUnknown(PVD));
    parameters.add(OOTS, "oots", () -> new ParameterUnknown(OOTS));

    // Support obsolete echconfig name as an alias for ech
    parameters.addAlias(ECH, "echconfig");
  }

  public abstract static class ParameterBase implements Serializable {
    public ParameterBase() {}

    public abstract int getKey();

    public abstract void fromWire(byte[] bytes) throws IOException;

    public abstract void fromString(String string) throws IOException;

    public abstract byte[] toWire();

    @Override
    public abstract String toString();

    /**
     * Split string on commas, but not if the comma is escaped with a {@code \} (backslash).
     *
     * @deprecated This uses a regex and doesn't work as intended. Use a proper parser instead.
     */
    @Deprecated
    public static String[] splitStringWithEscapedCommas(String string) {
      return string.split("(?<!\\\\),");
    }
  }

  public static class ParameterMandatory extends ParameterBase {
    private final List<Integer> values;

    public ParameterMandatory() {
      values = new ArrayList<>();
    }

    public ParameterMandatory(List<Integer> values) {
      this.values = new ArrayList<>(values);
      this.values.sort(Integer::compareTo);
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
      int maxKey = 0;
      while (in.remaining() >= 2) {
        int key = in.readU16();
        if (key < maxKey) {
          // In wire format, the keys are represented by their numeric values in network byte order,
          // concatenated in strictly increasing numeric order.
          throw new WireParseException("Illegal mandatory value, " + key + " is out of order");
        }
        maxKey = key;
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

      // section-8: To enable simpler parsing, this SvcParamValue MUST NOT contain escape sequences
      for (String str : string.split(",")) {
        int key = parameters.getValue(str);
        if (key == MANDATORY) {
          throw new TextParseException("Key mandatory must not appear in its own list");
        }

        if (values.contains(key)) {
          throw new TextParseException("Duplicate key " + str + " not allowed in mandatory list");
        }

        values.add(key);
      }

      // In wire format, the keys are represented by their numeric values in network byte order,
      // concatenated in strictly increasing numeric order.
      values.sort(Integer::compareTo);
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
    private static final byte[] H2 = new byte[] {'h', '2'};
    private static final byte[] H3 = new byte[] {'h', '3'};

    private static final DecimalFormat byteFormat = new DecimalFormat();

    static {
      byteFormat.setMinimumIntegerDigits(3);
    }

    private final List<byte[]> values;

    public ParameterAlpn() {
      values = new ArrayList<>();
    }

    public ParameterAlpn(List<String> values) throws TextParseException {
      this.values = new ArrayList<>();
      for (String str : values) {
        this.values.add(byteArrayFromString(str));
      }
    }

    public List<String> getValues() {
      List<String> result = new ArrayList<>();
      for (byte[] str : values) {
        StringBuilder sb = new StringBuilder();
        for (byte c : str) {
          if (c >= ' ' && c <= '~') {
            sb.append((char) c);
          } else {
            sb.append('\\');
            sb.append(byteFormat.format(c & 0xFF));
          }
        }

        result.add(sb.toString());
      }

      return result;
    }

    public List<byte[]> getRawValues() {
      return new ArrayList<>(values);
    }

    @Override
    public int getKey() {
      return ALPN;
    }

    @Override
    @SuppressWarnings("java:S131")
    public void fromWire(byte[] bytes) throws IOException {
      values.clear();
      // Optimize for the common case: h2 / h3 / h2,h3 / h3,h2
      // Out of the 50'000 most-commonly visited domains, about 1/5th have an HTTPS record.
      // From those, only 17 contain other values than the common ones. 40 include http/1.1, with
      // gentoo.com being the only outlier announcing pre-RFC http/3 (alpn=h2,h3,h3-29,h3-27)
      switch (bytes.length) {
        case 0:
        case 1:
          throw new WireParseException("invalid alpn value (empty)");

        case 2:
          if (bytes[0] == 1) {
            values.add(new byte[] {bytes[1]});
            return;
          } else {
            throw new WireParseException("invalid alpn value, end of input");
          }

        case 3:
          // string length, string h*
          if (bytes[0] == 2 && bytes[1] == 'h') {
            // h2 or h3
            if (bytes[2] == '2') {
              values.add(H2);
              return;
            } else if (bytes[2] == '3') {
              values.add(H3);
              return;
            }
          }
          break;

        case 6:
          // string length, h*
          if (bytes[0] == 2
              && bytes[1] == 'h'
              // string length, h*
              && bytes[3] == 2
              && bytes[4] == 'h') {

            // h2,h3 or h3,h2
            if (bytes[2] == '2' && bytes[5] == '3') {
              values.add(H2);
              values.add(H3);
              return;
            } else if (bytes[2] == '3' && bytes[5] == '2') {
              values.add(H3);
              values.add(H2);
              return;
            }
          }
          break;
      }

      // Parse all non-well-known alpn values generically
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

      // Appendix A.1:
      // Decode the value as a char-string first, then apply comma-separated list decoding
      DNSOutput out = new DNSOutput();
      int pos = 0;
      int digits = 0;
      int val = 0;
      boolean charStringEscape = false;
      boolean commaEscape = false;
      while (pos < string.length()) {
        char c = string.charAt(pos++);
        byte b;
        if (c == '\\' && !charStringEscape) {
          charStringEscape = true;
          digits = 0;
          val = 0;
          continue;
        } else if (charStringEscape && c >= '0' && c <= '9' && digits < 3) {
          val *= 10;
          val += (c - '0');
          if (++digits == 3) {
            b = (byte) val;
            charStringEscape = false;
          } else {
            continue;
          }
        } else {
          b = (byte) c;
          charStringEscape = false;
        }

        if (b == '\\' && !commaEscape) {
          commaEscape = true;
        } else if (commaEscape) {
          if ((b == ',' || b == '\\')) {
            out.writeU8(b);
            commaEscape = false;
          } else {
            throw new TextParseException("bad escape");
          }
        } else if (b == ',') {
          if (out.current() == 0) {
            throw new TextParseException("empty identifier");
          }

          values.add(out.toByteArray());
          out = new DNSOutput();
        } else {
          out.writeU8(b & 0xFF);
        }
      }

      if (out.current() == 0) {
        throw new TextParseException("empty identifier");
      }

      values.add(out.toByteArray());
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
      boolean needsQuote = false;
      StringBuilder sb = new StringBuilder();
      for (byte[] str : values) {
        if (sb.length() > 0) {
          sb.append(',');
        }

        for (byte c : str) {
          if (c == ' ' || c == '"' || c == ';' || c == '(' || c == ')') {
            // Appendix-A: quoted
            if (!needsQuote) {
              sb.insert(0, '"');
              needsQuote = true;
            }
            sb.append('\\');
            sb.append((char) c);
          } else if (c >= 0x21 && c <= 0x7e) {
            // VCHAR
            if (c == ',') {
              // Appendix-A.1: comma needs escaping
              sb.append("\\092,");
            } else if (c == '\\') {
              // Appendix-A.1: backslash needs escaping
              sb.append("\\\\\\092");
            } else {
              // Appendix-A: non-special
              sb.append((char) c);
            }
          } else {
            // Appendix-A: escaped dec-octet
            sb.append('\\');
            sb.append(byteFormat.format(c & 0xFF));
          }
        }
      }

      if (needsQuote) {
        sb.append('"');
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

      int parsedPort;
      try {
        parsedPort = Integer.parseInt(string);
      } catch (NumberFormatException nfe) {
        throw new TextParseException("Invalid port number: " + string, nfe);
      }

      if (parsedPort >= 0 && parsedPort <= 65535) {
        port = parsedPort;
      } else {
        throw new TextParseException("Invalid port number: " + string);
      }
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
      List<Inet4Address> result = new LinkedList<>();
      for (byte[] bytes : addresses) {
        InetAddress address = InetAddress.getByAddress(bytes);
        if (address instanceof Inet4Address) {
          result.add((Inet4Address) address);
        }
      }
      return result;
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

  public static class ParameterEch extends ParameterBase {
    private byte[] data;

    public ParameterEch() {}

    public ParameterEch(byte[] data) {
      this.data = data;
      if (data == null || data.length == 0) {
        throw new IllegalArgumentException("data is required and must be non-empty");
      }
    }

    public byte[] getData() {
      return data;
    }

    @Override
    public int getKey() {
      return ECH;
    }

    @Override
    public void fromWire(byte[] bytes) throws WireParseException {
      data = bytes;
      if (data == null || data.length == 0) {
        throw new WireParseException("data is required and must be non-empty");
      }
    }

    @Override
    public void fromString(String string) throws TextParseException {
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty base64 value must be specified for ech");
      }
      data = base64.fromString(string);
    }

    @Override
    public byte[] toWire() {
      return data;
    }

    @Override
    public String toString() {
      return base64.toString(data);
    }
  }

  /**
   * Pre-RFC class for {@link ParameterEch}.
   *
   * @deprecated use {@link ParameterEch}
   */
  @Deprecated
  public static class ParameterEchConfig extends ParameterBase {
    private byte[] data;

    public ParameterEchConfig() {}

    public ParameterEchConfig(byte[] data) {
      this.data = data;
      if (data == null || data.length == 0) {
        throw new IllegalArgumentException("data is required and must be non-empty");
      }
    }

    public byte[] getData() {
      return data;
    }

    @Override
    public int getKey() {
      return ECHCONFIG;
    }

    @Override
    public void fromWire(byte[] bytes) throws WireParseException {
      data = bytes;
      if (data == null || data.length == 0) {
        throw new WireParseException("data is required and must be non-empty");
      }
    }

    @Override
    public void fromString(String string) throws TextParseException {
      if (string == null || string.isEmpty()) {
        throw new TextParseException("Non-empty base64 value must be specified for echconfig");
      }
      data = base64.fromString(string);
    }

    @Override
    public byte[] toWire() {
      return data;
    }

    @Override
    public String toString() {
      return base64.toString(data);
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
      List<Inet6Address> result = new LinkedList<>();
      for (byte[] bytes : addresses) {
        InetAddress address = InetAddress.getByAddress(bytes);
        if (address instanceof Inet6Address) {
          result.add((Inet6Address) address);
        }
      }
      return result;
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
          sb.append(addr.getHostAddress());
        } catch (UnknownHostException e) {
          // should not happen, but returning null and throwing is bad
          return e.getMessage();
        }
      }
      return sb.toString();
    }
  }

  public static class ParameterUnknown extends ParameterBase {
    private final int key;
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
      return byteArrayToStringAutoQuote(value);
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
    for (Map.Entry<Integer, ParameterBase> entry : svcParams.entrySet()) {
      sb.append(" ");
      sb.append(parameters.getText(entry.getKey()));
      ParameterBase param = entry.getValue();
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
      int indexOfEquals = t.value().indexOf('=');
      if (indexOfEquals == -1) {
        // No "=" is key with no value case, leave value string as null
        keyStr = t.value();
      } else if (indexOfEquals == t.value().length() - 1) {
        // Ends with "=" means the next token is quoted string with the value
        keyStr = t.value().substring(0, indexOfEquals);
        Tokenizer.Token valueToken = st.get();
        if (!valueToken.isString()) {
          throw new TextParseException("Expected value for parameter key '" + keyStr + "'");
        }
        valueStr = valueToken.value();
      } else if (indexOfEquals > 0) {
        // If "=" is in the middle then need to split the key and value from this token
        keyStr = t.value().substring(0, indexOfEquals);
        valueStr = t.value().substring(indexOfEquals + 1);
      } else {
        throw new TextParseException("Expected valid parameter key=value for '" + t.value() + "'");
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
    for (Map.Entry<Integer, ParameterBase> entry : svcParams.entrySet()) {
      out.writeU16(entry.getKey());
      ParameterBase param = entry.getValue();
      byte[] value = param.toWire();
      out.writeU16(value.length);
      out.writeByteArray(value);
    }
  }
}

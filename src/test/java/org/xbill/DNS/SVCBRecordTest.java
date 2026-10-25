// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

public class SVCBRecordTest {
  @Test
  @SuppressWarnings("deprecation")
  void createParams() throws UnknownHostException, TextParseException {
    List<Integer> mandatoryList = Arrays.asList(SVCBRecord.ALPN, SVCBRecord.IPV4HINT);
    SVCBRecord.ParameterMandatory mandatory = new SVCBBase.ParameterMandatory(mandatoryList);
    assertEquals(SVCBRecord.MANDATORY, mandatory.getKey());
    assertEquals(mandatoryList, mandatory.getValues());
    assertThat(mandatory).hasToString("alpn,ipv4hint");

    List<String> alpnList = Arrays.asList("h2", "h3");
    SVCBRecord.ParameterAlpn alpn = new SVCBRecord.ParameterAlpn(alpnList);
    assertEquals(SVCBRecord.ALPN, alpn.getKey());
    assertEquals(alpnList, alpn.getValues());

    SVCBRecord.ParameterPort port = new SVCBBase.ParameterPort(8443);
    assertEquals(SVCBRecord.PORT, port.getKey());
    assertEquals(8443, port.getPort());

    List<Inet4Address> ipv4List =
        Collections.singletonList((Inet4Address) InetAddress.getByName("1.2.3.4"));
    SVCBRecord.ParameterIpv4Hint ipv4hint = new SVCBRecord.ParameterIpv4Hint(ipv4List);
    assertEquals(SVCBRecord.IPV4HINT, ipv4hint.getKey());
    assertEquals(ipv4List, ipv4hint.getAddresses());

    byte[] data = {'a', 'b', 'c'};
    SVCBBase.ParameterEch ech = new SVCBBase.ParameterEch(data);
    assertEquals(SVCBRecord.ECH, ech.getKey());
    assertEquals(data, ech.getData());

    SVCBRecord.ParameterEchConfig echconfig = new SVCBRecord.ParameterEchConfig(data);
    assertEquals(SVCBRecord.ECHCONFIG, echconfig.getKey());
    assertEquals(data, echconfig.getData());

    List<Inet6Address> ipv6List =
        Collections.singletonList((Inet6Address) InetAddress.getByName("2001:db8::1"));
    SVCBRecord.ParameterIpv6Hint ipv6hint = new SVCBRecord.ParameterIpv6Hint(ipv6List);
    assertEquals(SVCBRecord.IPV6HINT, ipv6hint.getKey());
    assertEquals(ipv6List, ipv6hint.getAddresses());

    byte[] value = {0, 1, 2, 3};
    SVCBRecord.ParameterUnknown unknown = new SVCBRecord.ParameterUnknown(33, value);
    assertEquals(33, unknown.getKey());
    assertEquals(value, unknown.getValue());
  }

  @Test
  void unknownParameterWithSpaceIsQuoted1() {
    SVCBRecord.ParameterUnknown unknown =
        new SVCBRecord.ParameterUnknown(33, new byte[] {'a', ' ', 'b'});
    assertThat(unknown.getKey()).isEqualTo(33);
    assertThat(unknown).hasToString("\"a b\"");
  }

  @Test
  void unknownParameterWithSpaceIsQuoted2() throws IOException {
    String presentation = "1 foo.example.com. key667=\"a b\"";
    SVCBRecord r = new SVCBRecord();
    r.rdataFromString(new Tokenizer(presentation), Name.root);
    assertThat(r.getSvcParamValue(667))
        .isInstanceOf(SVCBRecord.ParameterUnknown.class)
        .extracting(p -> ((SVCBRecord.ParameterUnknown) p).getValue())
        .isEqualTo(new byte[] {'a', ' ', 'b'});
    assertThat(r.rdataToString()).hasToString(presentation);
  }

  @SuppressWarnings("deprecation")
  @Test
  void echCtorDataIsRequired() {
    assertThatThrownBy(() -> new SVCBBase.ParameterEch(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("data is required and must be non-empty");
    assertThatThrownBy(() -> new SVCBBase.ParameterEch(new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("data is required and must be non-empty");
    assertThatThrownBy(() -> new SVCBBase.ParameterEchConfig(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("data is required and must be non-empty");
    assertThatThrownBy(() -> new SVCBBase.ParameterEchConfig(new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("data is required and must be non-empty");
  }

  @SuppressWarnings("deprecation")
  @Test
  void echFromWireDataIsRequired() {
    SVCBBase.ParameterEch ech = new SVCBBase.ParameterEch();
    assertThatThrownBy(() -> ech.fromWire(null))
        .isInstanceOf(WireParseException.class)
        .hasMessage("data is required and must be non-empty");
    assertThatThrownBy(() -> ech.fromWire(new byte[0]))
        .isInstanceOf(WireParseException.class)
        .hasMessage("data is required and must be non-empty");

    SVCBBase.ParameterEchConfig echc = new SVCBBase.ParameterEchConfig();
    assertThatThrownBy(() -> echc.fromWire(null))
        .isInstanceOf(WireParseException.class)
        .hasMessage("data is required and must be non-empty");
    assertThatThrownBy(() -> echc.fromWire(new byte[0]))
        .isInstanceOf(WireParseException.class)
        .hasMessage("data is required and must be non-empty");
  }

  @SuppressWarnings("deprecation")
  @ParameterizedTest
  @NullAndEmptySource
  void echFromStringDataIsRequired(String input) {
    SVCBBase.ParameterEch ech = new SVCBBase.ParameterEch();
    assertThatThrownBy(() -> ech.fromString(input))
        .isInstanceOf(TextParseException.class)
        .hasMessage("Non-empty base64 value must be specified for ech");

    SVCBBase.ParameterEchConfig echc = new SVCBBase.ParameterEchConfig();
    assertThatThrownBy(() -> echc.fromString(input))
        .isInstanceOf(TextParseException.class)
        .hasMessage("Non-empty base64 value must be specified for echconfig");
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 65536})
  void svcbPortRange(int portNumber) {
    SVCBRecord.ParameterPort port = new SVCBBase.ParameterPort();
    String portAsString = Integer.toString(portNumber);
    assertThatThrownBy(() -> port.fromString(portAsString)).isInstanceOf(TextParseException.class);
    assertEquals(SVCBRecord.PORT, port.getKey());
  }

  private static SVCBBase getSvcbFromPresentation(String presentation) throws IOException {
    try (Master m =
        new Master(
            new ByteArrayInputStream(presentation.getBytes(StandardCharsets.UTF_8)),
            Name.root,
            0)) {
      return (SVCBBase) m.nextRecord();
    }
  }

  private static class TestVector {
    final String presentation;
    final SVCBBase svcb;
    final String generic;
    final UNKRecord unkrecord;
    final String wire;
    final byte[] wireBytes;

    public TestVector(String presentation, String generic, String wire) throws IOException {
      this.presentation = presentation;
      this.generic = generic;
      this.wire = wire;

      svcb = getSvcbFromPresentation(presentation);
      DNSOutput out = new DNSOutput();
      svcb.rrToWire(out, null, false);

      unkrecord = (UNKRecord) Record.fromString(Name.root, 0, DClass.IN, 0, generic, Name.root);
      wireBytes = parseRfcTestVectorWireFormat(wire);

      assertThat(unkrecord.getData())
          .as("Data of UNKRecord must match wire bytes")
          .isEqualTo(wireBytes);
      assertThat(out.toByteArray())
          .as("SVCBBase.rrToWire must match wire bytes")
          .isEqualTo(wireBytes);
    }

    private static byte[] parseRfcTestVectorWireFormat(String input) {
      DNSOutput out = new DNSOutput();
      int pos = 0;
      while (pos < input.length()) {
        char c = input.charAt(pos++);
        if (c == '\\') {
          if (input.charAt(pos) == 'x') {
            // skip the x
            pos++;
            char c1 = input.charAt(pos++);
            char c2 = input.charAt(pos++);
            out.writeU8(Integer.parseInt(String.valueOf(c1) + c2, 16));
          } else {
            out.writeU8(c);
          }
        } else if (c == '#') {
          // skip everything on the same line after a semicolon
          while (pos < input.length()) {
            if (input.charAt(pos++) == '\n') {
              break;
            }
          }
        } else if (c != ' ' && c != '\n') {
          out.writeU8(c);
        }
      }
      return out.toByteArray();
    }
  }

  @Test
  @DisplayName("D.1. AliasMode")
  void appendixDTestVectors_1() throws IOException {
    String presentation = "example.com.   HTTPS   0 foo.example.com.";
    String generic =
        "\\# 19 (\n"
            + "00 00                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
            + ")";
    String wire =
        "\\x00\\x00                                           # priority\n"
            + "\\x03foo\\x07example\\x03com\\x00                      # target";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isZero();
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.com."));
  }

  @Test
  @DisplayName("D.2. ServiceMode: TargetName Is \".\"")
  void appendixDTestVectors_2a() throws IOException {
    String presentation = "example.com.   SVCB   1 .";
    String generic =
        "\\# 3 (\n" + "00 01      ; priority\n" + "00         ; target (root label)\n" + ")";
    String wire = "\\x00\\x01   # priority\n" + "\\x00       # target (root label)";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isOne();
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.root);
  }

  @Test
  @DisplayName("D.2. ServiceMode: Specifies a Port")
  void appendixDTestVectors_2b() throws IOException {
    String presentation = "example.com.   SVCB   16 foo.example.com. port=53";
    String generic =
        "\\# 25 (\n"
            + "00 10                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
            + "00 03                                              ; key 3\n"
            + "00 02                                              ; length 2\n"
            + "00 35                                              ; value\n"
            + ")";
    String wire =
        "\\x00\\x10                                           # priority\n"
            + "\\x03foo\\x07example\\x03com\\x00                      # target\n"
            + "\\x00\\x03                                           # key 3\n"
            + "\\x00\\x02                                           # length 2\n"
            + "\\x00\\x35                                           # value";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isEqualTo(16);
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.com."));
    assertThat(v.svcb.getSvcParamValue(SVCBBase.PORT))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterPort.class))
        .extracting(SVCBBase.ParameterPort::getPort)
        .isEqualTo(53);
  }

  @Test
  @DisplayName("D.2. ServiceMode: A Generic Key and Unquoted Value")
  void appendixDTestVectors_2c() throws IOException {
    String presentation = "example.com.   SVCB   1 foo.example.com. key667=hello";
    String generic =
        "\\# 28 (\n"
            + "00 01                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
            + "02 9b                                              ; key 667\n"
            + "00 05                                              ; length 5\n"
            + "68 65 6c 6c 6f                                     ; value\n"
            + ")";
    String wire =
        "\\x00\\x01                                           # priority\n"
            + "\\x03foo\\x07example\\x03com\\x00                      # target\n"
            + "\\x02\\x9b                                           # key 667\n"
            + "\\x00\\x05                                           # length 5\n"
            + "hello                                              # value";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isOne();
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.com."));
    assertThat(v.svcb.getSvcParamValue(667))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterUnknown.class))
        .extracting(SVCBBase.ParameterUnknown::getValue)
        .isEqualTo("hello".getBytes(StandardCharsets.ISO_8859_1));
  }

  @Test
  @DisplayName("D.2. ServiceMode: A Generic Key and Quoted Value with a Decimal Escape")
  void appendixDTestVectors_2d() throws IOException {
    String presentation = "example.com.   SVCB   1 foo.example.com. key667=\"hello\\210qoo\"";
    String generic =
        "\\# 32 (\n"
            + "00 01                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
            + "02 9b                                              ; key 667\n"
            + "00 09                                              ; length 9\n"
            + "68 65 6c 6c 6f d2 71 6f 6f                         ; value\n"
            + ")";
    String wire =
        "\\x00\\x01                                           # priority\n"
            + "\\x03foo\\x07example\\x03com\\x00                      # target\n"
            + "\\x02\\x9b                                           # key 667\n"
            + "\\x00\\x09                                           # length 9\n"
            + "hello\\xd2qoo                                       # value";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isOne();
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.com."));
    assertThat(v.svcb.getSvcParamValue(667))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterUnknown.class))
        .extracting(SVCBBase.ParameterUnknown::getValue)
        .isEqualTo(("hello" + ((char) 210) + "qoo").getBytes(StandardCharsets.ISO_8859_1));
  }

  @Test
  @DisplayName("D.2. ServiceMode: Two Quoted IPv6 Hints")
  void appendixDTestVectors_2e() throws IOException {
    String presentation =
        "example.com.   SVCB   1 foo.example.com. (\n"
            + "                      ipv6hint=\"2001:db8::1,2001:db8::53:1\"\n"
            + "                      )";
    String generic =
        "\\# 55 (\n"
            + "00 01                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target\n"
            + "00 06                                              ; key 6\n"
            + "00 20                                              ; length 32\n"
            + "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01    ; first address\n"
            + "20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01    ; second address\n"
            + ")";
    String wire =
        "\\x00\\x01                                           # priority\n"
            + "\\x03foo\\x07example\\x03com\\x00                      # target\n"
            + "\\x00\\x06                                           # key 6\n"
            + "\\x00\\x20                                           # length 32\n"
            + "\\x20\\x01\\x0d\\xb8\\x00\\x00\\x00\\x00\n"
            + "     \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01              # first address\n"
            + "\\x20\\x01\\x0d\\xb8\\x00\\x00\\x00\\x00\n"
            + "     \\x00\\x00\\x00\\x00\\x00\\x53\\x00\\x01              # second address";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isOne();
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.com."));
    assertThat(v.svcb.getSvcParamValue(SVCBBase.IPV6HINT))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterIpv6Hint.class))
        .extracting(
            p -> {
              try {
                return p.getAddresses();
              } catch (UnknownHostException e) {
                throw new RuntimeException(e);
              }
            })
        .asInstanceOf(InstanceOfAssertFactories.list(Inet6Address.class))
        .containsExactly(
            (Inet6Address) Inet6Address.getByName("2001:db8::1"),
            (Inet6Address) Inet6Address.getByName("2001:db8::53:1"));
  }

  @Test
  @DisplayName("D.2. ServiceMode: An IPv6 Hint Using the Embedded IPv4 Syntax")
  void appendixDTestVectors_2f() throws IOException {
    String presentation =
        "example.com.   SVCB   1 example.com. (\n"
            + "                        ipv6hint=\"2001:db8:122:344::192.0.2.33\"\n"
            + "                        )";
    String generic =
        "\\# 35 (\n"
            + "00 01                                              ; priority\n"
            + "07 65 78 61 6d 70 6c 65 03 63 6f 6d 00             ; target\n"
            + "00 06                                              ; key 6\n"
            + "00 10                                              ; length 16\n"
            + "20 01 0d b8 01 22 03 44 00 00 00 00 c0 00 02 21    ; address\n"
            + ")";
    String wire =
        "\\x00\\x01                                           # priority\n"
            + "\\x07example\\x03com\\x00                             # target\n"
            + "\\x00\\x06                                           # key 6\n"
            + "\\x00\\x10                                           # length 16\n"
            + "\\x20\\x01\\x0d\\xb8\\x01\\x22\\x03\\x44\n"
            + "     \\x00\\x00\\x00\\x00\\xc0\\x00\\x02\\x21              # address";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isOne();
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("example.com."));
    assertThat(v.svcb.getSvcParamValue(SVCBBase.IPV6HINT))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterIpv6Hint.class))
        .extracting(
            p -> {
              try {
                return p.getAddresses();
              } catch (UnknownHostException e) {
                throw new RuntimeException(e);
              }
            })
        .asInstanceOf(InstanceOfAssertFactories.list(Inet6Address.class))
        .containsExactly((Inet6Address) Inet6Address.getByName("2001:db8:122:344::192.0.2.33"));
  }

  @Test
  @DisplayName(
      "D.2. ServiceMode: SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format")
  void appendixDTestVectors_2g() throws IOException {
    String presentation =
        "example.com.   SVCB   16 foo.example.org. (\n"
            + "                      alpn=h2,h3-19 mandatory=ipv4hint,alpn\n"
            + "                      ipv4hint=192.0.2.1\n"
            + "                      )";
    String generic =
        "\\# 48 (\n"
            + "00 10                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
            + "00 00                                              ; key 0\n"
            + "00 04                                              ; param length 4\n"
            + "00 01                                              ; value: key 1\n"
            + "00 04                                              ; value: key 4\n"
            + "00 01                                              ; key 1\n"
            + "00 09                                              ; param length 9\n"
            + "02                                                 ; alpn length 2\n"
            + "68 32                                              ; alpn value\n"
            + "05                                                 ; alpn length 5\n"
            + "68 33 2d 31 39                                     ; alpn value\n"
            + "00 04                                              ; key 4\n"
            + "00 04                                              ; param length 4\n"
            + "c0 00 02 01                                        ; param value\n"
            + ")";
    String wire =
        "\\x00\\x10                                           # priority\n"
            + "\\x03foo\\x07example\\x03org\\x00                      # target\n"
            + "\\x00\\x00                                           # key 0\n"
            + "\\x00\\x04                                           # param length 4\n"
            + "\\x00\\x01                                           # value: key 1\n"
            + "\\x00\\x04                                           # value: key 4\n"
            + "\\x00\\x01                                           # key 1\n"
            + "\\x00\\x09                                           # param length 9\n"
            + "\\x02                                               # alpn length 2\n"
            + "h2                                                 # alpn value\n"
            + "\\x05                                               # alpn length 5\n"
            + "h3-19                                              # alpn value\n"
            + "\\x00\\x04                                           # key 4\n"
            + "\\x00\\x04                                           # param length 4\n"
            + "\\xc0\\x00\\x02\\x01                                   # param value";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isEqualTo(16);
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.org."));
    assertThat(v.svcb.getSvcParamValue(SVCBBase.ALPN))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterAlpn.class))
        .extracting(SVCBBase.ParameterAlpn::getValues)
        .asInstanceOf(InstanceOfAssertFactories.list(String.class))
        .containsExactly("h2", "h3-19");
    assertThat(v.svcb.getSvcParamValue(SVCBBase.MANDATORY))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterMandatory.class))
        .extracting(SVCBBase.ParameterMandatory::getValues)
        .asInstanceOf(InstanceOfAssertFactories.list(Integer.class))
        .containsExactly(SVCBBase.ALPN, SVCBBase.IPV4HINT);
    assertThat(v.svcb.getSvcParamValue(SVCBBase.IPV4HINT))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterIpv4Hint.class))
        .extracting(
            p -> {
              try {
                return p.getAddresses();
              } catch (UnknownHostException e) {
                throw new RuntimeException(e);
              }
            })
        .asInstanceOf(InstanceOfAssertFactories.list(Inet4Address.class))
        .containsExactly((Inet4Address) Inet6Address.getByName("192.0.2.1"));
  }

  @ParameterizedTest
  @DisplayName(
      "D.2. ServiceMode: An \"alpn\" Value with an Escaped Comma and an Escaped Backslash in Two Presentation Formats")
  @ValueSource(
      strings = {
        "example.com.   SVCB   16 foo.example.org. alpn=\"f\\\\\\\\oo\\\\,bar,h2\"",
        "example.com.   SVCB   16 foo.example.org. alpn=f\\\\\\092oo\\092,bar,h2",
      })
  void appendixDTestVectors_2h(String presentation) throws IOException {
    String generic =
        "\\# 35 (\n"
            + "00 10                                              ; priority\n"
            + "03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target\n"
            + "00 01                                              ; key 1\n"
            + "00 0c                                              ; param length 12\n"
            + "08                                                 ; alpn length 8\n"
            + "66 5c 6f 6f 2c 62 61 72                            ; alpn value\n"
            + "02                                                 ; alpn length 2\n"
            + "68 32                                              ; alpn value\n"
            + ")";
    String wire =
        "\\x00\\x10                                           # priority\n"
            + "\\x03foo\\x07example\\x03org\\x00                      # target\n"
            + "\\x00\\x01                                           # key 1\n"
            + "\\x00\\x0c                                           # param length 12\n"
            + "\\x08                                               # alpn length 8\n"
            + "f\\oo,bar                                           # alpn value\n"
            + "\\x02                                               # alpn length 2\n"
            + "h2                                                 # alpn value";
    TestVector v = new TestVector(presentation, generic, wire);
    assertThat(v.svcb.getSvcPriority()).isEqualTo(16);
    assertThat(v.svcb.getTargetName()).isEqualTo(Name.fromConstantString("foo.example.org."));
    assertThat(v.svcb.getSvcParamValue(SVCBBase.ALPN))
        .asInstanceOf(InstanceOfAssertFactories.type(SVCBBase.ParameterAlpn.class))
        .extracting(SVCBBase.ParameterAlpn::getValues)
        .asInstanceOf(InstanceOfAssertFactories.list(String.class))
        .containsExactly("f\\oo,bar", "h2");
    assertThat(v.svcb.rrToString())
        .hasToString("16 foo.example.org. alpn=f\\\\\\092oo\\092,bar,h2");
  }

  @Test
  @DisplayName("D.3. Failure Cases: Multiple Instances of the Same SvcParamKey")
  void appendixDTestVectors_3a() {
    assertThatThrownBy(
            () ->
                getSvcbFromPresentation(
                    "example.com.   SVCB   1 foo.example.com. (\n"
                        + "                       key123=abc key123=def\n"
                        + "                       )"))
        .isInstanceOf(TextParseException.class)
        .hasMessageContaining("Duplicate parameter key for 'key123'");
  }

  @ParameterizedTest
  @DisplayName("D.3. Failure Cases: Missing SvcParamValues That Must Be Non-Empty")
  @ValueSource(
      strings = {
        "example.com.   SVCB   1 foo.example.com. mandatory",
        "example.com.   SVCB   1 foo.example.com. alpn",
        "example.com.   SVCB   1 foo.example.com. port",
        "example.com.   SVCB   1 foo.example.com. ipv4hint",
        "example.com.   SVCB   1 foo.example.com. ipv6hint",
      })
  void appendixDTestVectors_3b(String presentation) {
    assertThatThrownBy(() -> getSvcbFromPresentation(presentation))
        .isInstanceOf(TextParseException.class)
        .hasMessageMatching("(Non-empty.*? list|Integer value) must be specified.*");
  }

  @Test
  @DisplayName("D.3. Failure Cases: The \"no-default-alpn\" SvcParamKey Value Must Be Empty")
  void appendixDTestVectors_3c() {
    assertThatThrownBy(
            () ->
                getSvcbFromPresentation(
                    "example.com.   SVCB   1 foo.example.com. no-default-alpn=abc"))
        .isInstanceOf(TextParseException.class)
        .hasMessage("No value can be specified for no-default-alpn");
  }

  @Test
  @DisplayName("D.3. Failure Cases: A Mandatory SvcParam Is Missing")
  void appendixDTestVectors_3d() {
    assertThatThrownBy(
            () ->
                getSvcbFromPresentation(
                    "example.com.   SVCB   1 foo.example.com. mandatory=key123"))
        .isInstanceOf(TextParseException.class)
        .hasMessageEndingWith("Not all mandatory SvcParams are specified");
  }

  @Test
  @DisplayName(
      "D.3. Failure Cases: The \"mandatory\" SvcParamKey Must Not Be Included in the Mandatory List")
  void appendixDTestVectors_3e() {
    assertThatThrownBy(
            () ->
                getSvcbFromPresentation(
                    "example.com.   SVCB   1 foo.example.com. mandatory=mandatory"))
        .isInstanceOf(TextParseException.class)
        .hasMessage("Key mandatory must not appear in its own list");
  }

  @Test
  @DisplayName(
      "D.3. Failure Cases: Multiple Instances of the Same SvcParamKey in the Mandatory List")
  void appendixDTestVectors_3f() {
    assertThatThrownBy(
            () ->
                getSvcbFromPresentation(
                    "example.com.   SVCB   1 foo.example.com. (\n"
                        + "                      mandatory=key123,key123 key123=abc\n"
                        + "                      )"))
        .isInstanceOf(TextParseException.class)
        .hasMessage("Duplicate key key123 not allowed in mandatory list");
  }

  @Test
  void createRecord() throws IOException {
    Name label = Name.fromString("test.com.");
    int svcPriority = 5;
    Name svcDomain = Name.fromString("svc.test.com.");
    SVCBRecord.ParameterMandatory mandatory = new SVCBRecord.ParameterMandatory();
    mandatory.fromString("alpn");
    SVCBRecord.ParameterAlpn alpn = new SVCBRecord.ParameterAlpn();
    alpn.fromString("h1,h2");
    SVCBRecord.ParameterIpv4Hint ipv4 = new SVCBRecord.ParameterIpv4Hint();
    ipv4.fromString("1.2.3.4,5.6.7.8");
    List<SVCBRecord.ParameterBase> params = Arrays.asList(mandatory, ipv4, alpn);
    SVCBRecord svcbRecord = new SVCBRecord(label, DClass.IN, 300, svcPriority, svcDomain, params);

    assertEquals(Type.SVCB, svcbRecord.getType());
    assertEquals(label, svcbRecord.getName());
    assertEquals(svcPriority, svcbRecord.getSvcPriority());
    assertEquals(svcDomain, svcbRecord.getTargetName());
    assertEquals(
        Arrays.asList(SVCBRecord.MANDATORY, SVCBRecord.ALPN, SVCBRecord.IPV4HINT).toString(),
        svcbRecord.getSvcParamKeys().toString());
    assertThat(svcbRecord.getSvcParamValue(SVCBRecord.MANDATORY)).hasToString("alpn");
    assertThat(svcbRecord.getSvcParamValue(SVCBRecord.ALPN)).hasToString("h1,h2");
    assertNull(svcbRecord.getSvcParamValue(1234));
    Options.unset("BINDTTL");
    Options.unset("noPrintIN");
    assertEquals(
        "test.com.\t\t300\tIN\tSVCB\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8",
        svcbRecord.toString());
  }

  @Test
  void createRecordDuplicateParam() throws IOException {
    Name label = Name.fromString("test.com.");
    Name svcDomain = Name.fromString("svc.test.com.");
    SVCBRecord.ParameterAlpn alpn = new SVCBRecord.ParameterAlpn();
    alpn.fromString("h1,h2");
    SVCBRecord.ParameterIpv4Hint ipv4 = new SVCBRecord.ParameterIpv4Hint();
    ipv4.fromString("1.2.3.4,5.6.7.8");
    List<SVCBRecord.ParameterBase> params = Arrays.asList(alpn, ipv4, alpn);
    assertThrows(
        IllegalArgumentException.class,
        () -> new SVCBRecord(label, DClass.IN, 300, 5, svcDomain, params));
  }

  @Test
  void aliasMode() throws IOException {
    String str = "0 a.b.c.";
    byte[] bytes = stringToWire(str);
    byte[] expected = {0, 0, 1, 'a', 1, 'b', 1, 'c', 0};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModeWithoutParameters() throws IOException {
    String str = "1 .";
    byte[] bytes = stringToWire(str);
    byte[] expected = {0, 1, 0};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModePort() throws IOException {
    String str = "1 . port=8443";
    byte[] bytes = stringToWire(str);
    byte[] expected = {0, 1, 0, 0, 3, 0, 2, 0x20, (byte) 0xFB};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "1 . alpn=h3",
        "1 . alpn=h2,h3",
        "1 . alpn=h3,h2",
        "1 . no-default-alpn",
        "1 . alpn=h3 no-default-alpn",
        "1 dotty\\.lotty.example.com. no-default-alpn",
        "1 h3pool. ech=1234",
        "1 h3pool. alpn=h2,h3 ech=1234",
        "3 . ipv4hint=4.5.6.7",
        "7 . alpn=h2 ipv4hint=4.5.6.7",
      })
  void serviceModes(String str) throws IOException {
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeIntKey() throws IOException {
    String str = "1 . 1=h3";
    assertEquals("1 . alpn=h3", stringToWireToString(str));
  }

  @Test
  void serviceModeMultiValue() throws IOException {
    String str = "1 . alpn=h2,h3";
    byte[] bytes = stringToWire(str);
    byte[] expected = {0, 1, 0, 0, 1, 0, 6, 2, 'h', '2', 2, 'h', '3'};
    assertThat(bytes).isEqualTo(expected);
    assertThat(wireToString(bytes)).isEqualTo(str);
  }

  @ParameterizedTest
  @ValueSource(strings = {"h2", "http", "\\250"})
  void serviceModeSimpleValue(String simpleValue) throws IOException {
    SVCBBase.ParameterAlpn alpn1 =
        new SVCBBase.ParameterAlpn(Collections.singletonList(simpleValue));
    assertThat(alpn1).hasToString(simpleValue);

    SVCBBase.ParameterAlpn alpn2 = new SVCBBase.ParameterAlpn();
    assertThat(alpn2.getRawValues()).isEmpty();
    alpn2.fromString(simpleValue);
    assertThat(alpn2).hasToString(simpleValue);
    assertThat(alpn2.getValues()).containsExactly(simpleValue);
  }

  @ParameterizedTest
  @ValueSource(strings = {"h2,", ",h2", "h2,,h3"})
  void serviceModeMissingIdentifier(String simpleValue) {
    SVCBBase.ParameterAlpn alpn = new SVCBBase.ParameterAlpn();
    assertThat(alpn.getRawValues()).isEmpty();
    assertThatThrownBy(() -> alpn.fromString(simpleValue))
        .isInstanceOf(TextParseException.class)
        .hasMessage("empty identifier");
  }

  @ParameterizedTest
  @ValueSource(strings = {"foo\\\\092,baz", "foo\\\\042baz"})
  void serviceModeBadEscape(String simpleValue) {
    SVCBBase.ParameterAlpn alpn = new SVCBBase.ParameterAlpn();
    assertThat(alpn.getRawValues()).isEmpty();
    assertThatThrownBy(() -> alpn.fromString(simpleValue))
        .isInstanceOf(TextParseException.class)
        .hasMessage("bad escape");
  }

  @Test
  void serviceModeQuotedValue() throws IOException {
    String str = "1 . alpn=\"h2,h3\"";
    assertThat(stringToWireToString(str)).isEqualTo("1 . alpn=h2,h3");
  }

  @Test
  void serviceModeQuotedEscapedValue1() throws IOException {
    SVCBBase.ParameterAlpn alpn =
        new SVCBBase.ParameterAlpn(Collections.singletonList("foo\"bar\",baz"));
    assertThat(alpn.getValues()).containsExactly("foo\"bar\",baz");
    assertThat(alpn).hasToString("\"foo\\\"bar\\\"\\092,baz\"");
  }

  @Test
  void serviceModeQuotedEscapedValue2() throws IOException {
    SVCBBase.ParameterAlpn alpnExpected = new SVCBBase.ParameterAlpn();
    alpnExpected.fromWire(
        new byte[] {
          10, 'h', '(', ',', ' ', '\n', ')', ';', '\\', '"', '2',
          10, 'f', '(', ',', ' ', '\n', ')', ';', '\\', '"', '3',
        });
    SVCBRecord svcbExpected =
        new SVCBRecord(
            Name.root, DClass.IN, 0, 1, Name.root, Collections.singletonList(alpnExpected));
    Master m =
        new Master(
            new ByteArrayInputStream(svcbExpected.toString().getBytes(StandardCharsets.UTF_8)),
            Name.root);
    SVCBRecord svcbFromString = (SVCBRecord) m.nextRecord();
    SVCBBase.ParameterAlpn alpnActual =
        (SVCBBase.ParameterAlpn) svcbFromString.getSvcParamValue(SVCBBase.ALPN);
    assertThat(alpnActual.getRawValues()).containsExactlyElementsOf(alpnExpected.getRawValues());
  }

  @ParameterizedTest
  @MethodSource("generateAlpnTestVectors")
  void serviceModeQuotedEscapedValue6(String input, String[] expected) throws IOException {
    SVCBBase.ParameterAlpn alpn = new SVCBBase.ParameterAlpn();
    alpn.fromString(input);
    assertThat(alpn.getValues()).containsExactly(expected);
  }

  private static Stream<Arguments> generateAlpnTestVectors() {
    return Stream.of(
        Arguments.of("h2", new String[] {"h2"}),
        Arguments.of("h2\\,h3,h\\\\\\\\4", new String[] {"h2", "h3", "h\\4"}),
        Arguments.of("h2,h3-19", new String[] {"h2", "h3-19"}),
        Arguments.of("f\\\\\\092oo\\092,bar,h2", new String[] {"f\\oo,bar", "h2"}),
        Arguments.of(
            "part1,part2,part3\\\\,part4\\\\\\\\",
            new String[] {"part1", "part2", "part3,part4\\"}),
        Arguments.of(
            "part1\\,\\p\\a\\r\\t2\\044part3\\092,part4\\092\\\\",
            new String[] {"part1", "part2", "part3,part4\\"}));
  }

  @Test
  void serviceModeAlpnEscapedBytes() throws IOException {
    String str = "1 . alpn=http/1.1,\\001aa\\003\\b,h2";
    String expectedStr = "1 . alpn=http/1.1,\\001aa\\003b,h2";
    byte[] bytes = stringToWire(str);
    byte[] expectedBytes = {
      0, 1, 0, 0, 1, 0, 18, 8, 104, 116, 116, 112, 47, 49, 46, 49, 5, 1, 97, 97, 3, 98, 2, 104, 50
    };
    assertThat(bytes).isEqualTo(expectedBytes);
    assertThat(wireToString(bytes)).isEqualTo(expectedStr);
  }

  @Test
  void serviceModeMandatoryAndOutOfOrder() throws IOException {
    String str = "1 . alpn=h3 no-default-alpn mandatory=alpn";
    assertEquals("1 . mandatory=alpn alpn=h3 no-default-alpn", stringToWireToString(str));
  }

  @Test
  void serviceModeEchOutOfOrder() throws IOException {
    String str = "1 h3pool. ech=1234 alpn=h2,h3";
    assertThat(stringToWireToString(str)).isEqualTo("1 h3pool. alpn=h2,h3 ech=1234");
  }

  @Test
  void serviceModeEchQuoted() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 ech=\"1234\"";
    assertThat(stringToWireToString(str)).isEqualTo("1 h3pool. alpn=h2,h3 ech=1234");
  }

  @Test
  void serviceModeObsoleteEchConfigName() throws IOException {
    String str = "1 . echconfig=1234";
    assertEquals("1 . ech=1234", stringToWireToString(str));
  }

  @Test
  void serviceModeIpv4HintList() throws IOException {
    String str = "5 . ipv4hint=4.5.6.7,8.9.1.2";
    byte[] bytes = stringToWire(str);
    byte[] expected = {0, 5, 0, 0, 4, 0, 8, 4, 5, 6, 7, 8, 9, 1, 2};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModeIpv4HintQuoted() throws IOException {
    String str = "5 . ipv4hint=\"4.5.6.7,8.9.1.2\"";
    assertEquals("5 . ipv4hint=4.5.6.7,8.9.1.2", stringToWireToString(str));
  }

  @Test
  void serviceModeIpv6Hint() throws IOException {
    String str = "9 . ipv6hint=2001:db8::1";
    assertEquals("9 . ipv6hint=2001:db8:0:0:0:0:0:1", stringToWireToString(str));
  }

  @Test
  void serviceModeIpv6HintMulti() throws IOException {
    String str = "2 . alpn=h2 ipv6hint=2001:db8::1,2001:db8::2";
    assertEquals(
        "2 . alpn=h2 ipv6hint=2001:db8:0:0:0:0:0:1,2001:db8:0:0:0:0:0:2",
        stringToWireToString(str));
  }

  @Test
  void serviceModeUnknownKey() throws IOException {
    String str = "6 . key12345=abcdefg\\012";
    assertThat(stringToWireToString(str)).isEqualTo(str);
  }

  @Test
  void serviceModeUnknownKeyBytes() throws IOException {
    String str = "8 . key23456=\\000\\001\\002\\003";
    byte[] bytes = stringToWire(str);
    byte[] expected = {0, 8, 0, 0x5B, (byte) 0xA0, 0, 4, 0, 1, 2, 3};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModeUnknownKeyEscapedChars() throws IOException {
    String str = "1 . key29=a\\b\\c";
    assertEquals("1 . key29=abc", stringToWireToString(str));
  }

  @Test
  void serviceModeUnknownKeyEscapedSlash() throws IOException {
    String str = "65535 . key29=a\\\\b\\\\c";
    assertThat(stringToWireToString(str)).isEqualTo(str);
  }

  @Test
  void serviceModeUnknownHighKey() throws IOException {
    String str = "65535 . key65535=abcdefg";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeUnknownKeyNoValue() throws IOException {
    String str = "65535 . key65535";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void masterFormatParsing() throws IOException {
    String str =
        "test.net. 86400 IN SOA test.net. test.net. 2020100900 3600 600 604800 300\n"
            + "test.net. 86400 IN NS ns1.test.net.\n"
            + "test.net. 300 IN HTTPS 0 www.test.net.\n"
            + "test.net. 300 IN SVCB 1 . alpn=h2\n"
            + "test.net. 300 IN HTTPS 1 .\n"
            + "www.test.net. 300 IN A 1.2.3.4\n";
    Master m = new Master(new ByteArrayInputStream(str.getBytes()));

    Record r = m.nextRecord();
    assertEquals(Type.SOA, r.getType());
    r = m.nextRecord();
    assertEquals(Type.NS, r.getType());
    r = m.nextRecord();
    assertEquals(Type.HTTPS, r.getType());
    assertEquals("0 www.test.net.", r.rdataToString());
    r = m.nextRecord();
    assertEquals(Type.SVCB, r.getType());
    assertEquals("1 . alpn=h2", r.rdataToString());
    r = m.nextRecord();
    assertEquals(Type.HTTPS, r.getType());
    assertEquals("1 .", r.rdataToString());
    r = m.nextRecord();
    assertEquals(Type.A, r.getType());
    assertEquals("1.2.3.4", r.rdataToString());
    r = m.nextRecord();
    assertNull(r);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "these are all garbage strings that should fail",
        "5 . ipv4hint=\"4.5.6.7\",\"8.9.1.2\"",
        "0 . alpn=h3",
        "1 . mandatory",
        "1 . alpn",
        "1 . port",
        "1 . ipv4hint",
        "1 . ech",
        "1 . ipv6hint",
        "1 . =1234",
        "1 . alpn=",
        "1 . =",
        "1 . sport=8443",
        "1 . mandatory=alpn,mandatory alpn=h1",
        "1 . mandatory=alpn,ipv4hint,alpn alpn=h1 ipv4hint=1.2.3.4",
        "1 . mandatory=alpn,ipv4hint alpn=h1",
        "1 . port=443a",
        "1 . no-default-alpn=true",
        "",
        "1 . port<5",
        "1 fred..harvey port=80",
        "1 . alpn=h2 alpn=h3",
        "1 . ipv4hint=2001:db8::1",
        "1 . ipv6hint=1.2.3.4",
        "-1 . port=80",
        "65535 . key65536=abcdefg",
        "65535 . key123a=abcdefg",
        "65535 . keyBlooie=abcdefg",
      })
  void invalidText(String str) {
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 65536, 84438})
  void portValueOutOfRange(int port) {
    String str = "1 . port=" + port;
    assertThatThrownBy(() -> stringToWire(str)).isInstanceOf(TextParseException.class);
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 65536})
  void svcPriorityInvalid(int port) {
    String str = port + " . port=443";
    assertThatThrownBy(() -> stringToWire(str)).isInstanceOf(TextParseException.class);
  }

  @Test
  void wireFormatTooShort() {
    byte[] wire = {0, 1, 0, 0, 1, 0, 10};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatTooLong() {
    byte[] wire = {0, 0, 0, 1};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatMandatoryTooLong() {
    byte[] wire = {0, 1, 0, 0, 0, 0, 3, 0, 1, 55};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatAlpnTooShort() {
    byte[] wire = {0, 1, 0, 0, 1, 0, 3, 10, 1, 55};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatNoDefaultAlpnTooLong() {
    byte[] wire = {0, 1, 0, 0, 2, 0, 1, 0};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatPortTooLong() {
    byte[] wire = {0, 1, 0, 0, 3, 0, 4, 0, 0, 0, 0};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatIpv4HintTooLong() {
    byte[] wire = {0, 1, 0, 0, 4, 0, 5, 1, 2, 3, 4, 5};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatIpv6HintTooShort() {
    byte[] wire = {0, 1, 0, 0, 6, 0, 2, 1, 2};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  public static byte[] stringToWire(String str) throws IOException {
    Tokenizer t = new Tokenizer(str);
    SVCBRecord svcbRecord = new SVCBRecord();
    svcbRecord.rdataFromString(t, null);
    DNSOutput out = new DNSOutput();
    svcbRecord.rrToWire(out, null, true);
    return out.toByteArray();
  }

  public static String wireToString(byte[] bytes) throws IOException {
    DNSInput in = new DNSInput(bytes);
    SVCBRecord svcbRecord = new SVCBRecord();
    svcbRecord.rrFromWire(in);
    return svcbRecord.rdataToString();
  }

  public static String stringToWireToString(String str) throws IOException {
    return wireToString(stringToWire(str));
  }
}

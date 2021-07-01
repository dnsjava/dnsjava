// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

public class SVCBRecordTest {
  @Test
  void createParams() throws UnknownHostException, TextParseException {
    List<Integer> mandatoryList = Arrays.asList(SVCBRecord.ALPN, SVCBRecord.IPV4HINT);
    SVCBRecord.ParameterMandatory mandatory = new SVCBBase.ParameterMandatory(mandatoryList);
    assertEquals(SVCBRecord.MANDATORY, mandatory.getKey());
    assertEquals(mandatoryList, mandatory.getValues());

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
    SVCBRecord record = new SVCBRecord(label, DClass.IN, 300, svcPriority, svcDomain, params);

    assertEquals(Type.SVCB, record.getType());
    assertEquals(label, record.getName());
    assertEquals(svcPriority, record.getSvcPriority());
    assertEquals(svcDomain, record.getTargetName());
    assertEquals(
        Arrays.asList(SVCBRecord.MANDATORY, SVCBRecord.ALPN, SVCBRecord.IPV4HINT).toString(),
        record.getSvcParamKeys().toString());
    assertEquals("alpn", record.getSvcParamValue(SVCBRecord.MANDATORY).toString());
    assertEquals("h1,h2", record.getSvcParamValue(SVCBRecord.ALPN).toString());
    assertEquals("h1,h2", record.getSvcParamValue(SVCBRecord.ALPN).toString());
    assertNull(record.getSvcParamValue(1234));
    Options.unset("BINDTTL");
    Options.unset("noPrintIN");
    assertEquals(
        "test.com.\t\t300\tIN\tSVCB\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8",
        record.toString());
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
    byte[] expected = new byte[] {0, 0, 1, 'a', 1, 'b', 1, 'c', 0};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModePort() throws IOException {
    String str = "1 . port=8443";
    byte[] bytes = stringToWire(str);
    byte[] expected = new byte[] {0, 1, 0, 0, 3, 0, 2, 0x20, (byte) 0xFB};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModeAlpn() throws IOException {
    String str = "1 . alpn=h3";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeNoDefaultAlpn() throws IOException {
    String str = "1 . no-default-alpn";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeMultiKey() throws IOException {
    String str = "1 . alpn=h3 no-default-alpn";
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
    byte[] expected = new byte[] {0, 1, 0, 0, 1, 0, 6, 2, 'h', '2', 2, 'h', '3'};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModeQuotedValue() throws IOException {
    String str = "1 . alpn=\"h2,h3\"";
    assertEquals("1 . alpn=h2,h3", stringToWireToString(str));
  }

  @Test
  void serviceModeQuotedEscapedValue() throws IOException {
    String str = "1 . alpn=\"h2\\,h3,h\\\\4\"";
    String expectedStr = "1 . alpn=h2\\,h3,h\\\\4";
    byte[] bytes = stringToWire(str);
    byte[] expectedBytes =
        new byte[] {0, 1, 0, 0, 1, 0, 10, 5, 104, 50, 44, 104, 51, 3, 104, '\\', 52};
    assertArrayEquals(bytes, expectedBytes);
    assertEquals(expectedStr, wireToString(bytes));
  }

  @Test
  void serviceModeAlpnEscapedBytes() throws IOException {
    String str = "1 . alpn=http/1.1,\\001aa\\003\\b,h2";
    String expectedStr = "1 . alpn=http/1.1,\\001aa\\003b,h2";
    byte[] bytes = stringToWire(str);
    byte[] expectedBytes =
        new byte[] {
          0, 1, 0, 0, 1, 0, 18, 8, 104, 116, 116, 112, 47, 49, 46, 49, 5, 1, 97, 97, 3, 98, 2, 104,
          50
        };
    assertArrayEquals(bytes, expectedBytes);
    assertEquals(expectedStr, wireToString(bytes));
  }

  @Test
  void serviceModeMandatoryAndOutOfOrder() throws IOException {
    String str = "1 . alpn=h3 no-default-alpn mandatory=alpn";
    assertEquals("1 . mandatory=alpn alpn=h3 no-default-alpn", stringToWireToString(str));
  }

  @Test
  void serviceModeEscapedDomain() throws IOException {
    String str = "1 dotty\\.lotty.example.com. no-default-alpn";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeEch() throws IOException {
    String str = "1 h3pool. ech=1234";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeEchMulti() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 ech=1234";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeEchOutOfOrder() throws IOException {
    String str = "1 h3pool. ech=1234 alpn=h2,h3";
    assertEquals("1 h3pool. alpn=h2,h3 ech=1234", stringToWireToString(str));
  }

  @Test
  void serviceModeEchQuoted() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 ech=\"1234\"";
    assertEquals("1 h3pool. alpn=h2,h3 ech=1234", stringToWireToString(str));
  }

  @Test
  void serviceModeIpv4Hint() throws IOException {
    String str = "3 . ipv4hint=4.5.6.7";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeIpv4HintList() throws IOException {
    String str = "5 . ipv4hint=4.5.6.7,8.9.1.2";
    byte[] bytes = stringToWire(str);
    byte[] expected = new byte[] {0, 5, 0, 0, 4, 0, 8, 4, 5, 6, 7, 8, 9, 1, 2};
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModeIpv4HintQuoted() throws IOException {
    String str = "5 . ipv4hint=\"4.5.6.7,8.9.1.2\"";
    assertEquals("5 . ipv4hint=4.5.6.7,8.9.1.2", stringToWireToString(str));
  }

  @Test
  void serviceModeIpv4HintMultiKey() throws IOException {
    String str = "7 . alpn=h2 ipv4hint=4.5.6.7";
    assertEquals(str, stringToWireToString(str));
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
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeUnknownKeyBytes() throws IOException {
    String str = "8 . key23456=\\000\\001\\002\\003";
    byte[] bytes = stringToWire(str);
    byte[] expected = new byte[] {0, 8, 0, 0x5B, (byte) 0xA0, 0, 4, 0, 1, 2, 3};
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
    assertEquals(str, stringToWireToString(str));
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
    assertEquals(Type.A, r.getType());
    assertEquals("1.2.3.4", r.rdataToString());
    r = m.nextRecord();
    assertNull(r);
  }

  @Test
  void invalidText() {
    String str = "these are all garbage strings that should fail";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void extraQuotesInParamValues() {
    String str = "5 . ipv4hint=\"4.5.6.7\",\"8.9.1.2\"";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void serviceModeWithoutParameters() {
    String str = "1 aliasmode.example.com.";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void aliasModeWithParameters() {
    String str = "0 . alpn=h3";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void zeroLengthMandatory() {
    String str = "1 . mandatory";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void zeroLengthAlpnValue() {
    String str = "1 . alpn";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void zeroLengthPortValue() {
    String str = "1 . port";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void zeroLengthIpv4Hint() {
    String str = "1 . ipv4hint";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void zeroLengthEch() {
    String str = "1 . ech";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void zeroLengthIpv6Hint() {
    String str = "1 . ipv6hint";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void emptyKey() {
    String str = "1 . =1234";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void emptyValue() {
    String str = "1 . alpn=";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void emptyKeyAndValue() {
    String str = "1 . =";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void unknownKey() {
    String str = "1 . sport=8443";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void mandatoryListWithSelf() {
    String str = "1 . mandatory=alpn,mandatory alpn=h1";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void mandatoryListWithDuplicate() {
    String str = "1 . mandatory=alpn,ipv4hint,alpn alpn=h1 ipv4hint=1.2.3.4";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void mandatoryListWithMissingParam() {
    String str = "1 . mandatory=alpn,ipv4hint alpn=h1";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void portValueTooLarge() {
    String str = "1 . port=84438";
    assertThrows(IllegalArgumentException.class, () -> stringToWire(str));
  }

  @Test
  void portValueCharAfterInt() {
    String str = "1 . port=443a";
    assertThrows(IllegalArgumentException.class, () -> stringToWire(str));
  }

  @Test
  void noDefaultAlpnWithValue() {
    String str = "1 . no-default-alpn=true";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void emptyString() {
    String str = "";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void noParamValues() {
    String str = "1 .";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void svcPriorityTooHigh() {
    String str = "65536 . port=443";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void invalidPortKey() {
    String str = "1 . port<5";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void invalidSvcDomain() {
    String str = "1 fred..harvey port=80";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void duplicateParamKey() {
    String str = "1 . alpn=h2 alpn=h3";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void invalidIpv4Hint() {
    String str = "1 . ipv4hint=2001:db8::1";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void invalidIpv6Hint() {
    String str = "1 . ipv6hint=1.2.3.4";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void negativeSvcPriority() {
    String str = "-1 . port=80";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void svcParamUnknownKeyTooHigh() {
    String str = "65535 . key65536=abcdefg";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void svcParamUnknownKeyCharAfterInt() {
    String str = "65535 . key123a=abcdefg";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void invalidSvcParamKey() {
    String str = "65535 . keyBlooie=abcdefg";
    assertThrows(TextParseException.class, () -> stringToWire(str));
  }

  @Test
  void wireFormatTooShort() {
    byte[] wire = new byte[] {0, 1, 0, 0, 1, 0, 10};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatTooLong() {
    byte[] wire = new byte[] {0, 0, 0, 1};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatMandatoryTooLong() {
    byte[] wire = new byte[] {0, 1, 0, 0, 0, 0, 3, 0, 1, 55};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatAlpnTooShort() {
    byte[] wire = new byte[] {0, 1, 0, 0, 1, 0, 3, 10, 1, 55};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatNoDefaultAlpnTooLong() {
    byte[] wire = new byte[] {0, 1, 0, 0, 2, 0, 1, 0};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatPortTooLong() {
    byte[] wire = new byte[] {0, 1, 0, 0, 3, 0, 4, 0, 0, 0, 0};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatIpv4HintTooLong() {
    byte[] wire = new byte[] {0, 1, 0, 0, 4, 0, 5, 1, 2, 3, 4, 5};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  @Test
  void wireFormatIpv6HintTooShort() {
    byte[] wire = new byte[] {0, 1, 0, 0, 6, 0, 2, 1, 2};
    assertThrows(WireParseException.class, () -> wireToString(wire));
  }

  public static byte[] stringToWire(String str) throws IOException {
    Tokenizer t = new Tokenizer(str);
    SVCBRecord record = new SVCBRecord();
    record.rdataFromString(t, null);
    DNSOutput out = new DNSOutput();
    record.rrToWire(out, null, true);
    return out.toByteArray();
  }

  public static String wireToString(byte[] bytes) throws IOException {
    DNSInput in = new DNSInput(bytes);
    SVCBRecord record = new SVCBRecord();
    record.rrFromWire(in);
    return record.rdataToString();
  }

  public static String stringToWireToString(String str) throws IOException {
    return wireToString(stringToWire(str));
  }
}

package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

public class SVCBRecordTest {
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
    List<SVCBRecord.ParameterBase> params = List.of(mandatory, ipv4, alpn);
    SVCBRecord record = new SVCBRecord(label, DClass.IN, 300, svcPriority, svcDomain, params);

    assertEquals(Type.SVCB, record.getType());
    assertEquals(label, record.getName());
    assertEquals(svcPriority, record.getSvcPriority());
    assertEquals(svcDomain, record.getTargetName());
    assertEquals(List.of(SVCBRecord.MANDATORY, SVCBRecord.ALPN, SVCBRecord.IPV4HINT).toString(), record.getSvcParamKeys().toString());
    assertEquals("alpn", record.getSvcParamValue(SVCBRecord.MANDATORY).toString());
    assertEquals("h1,h2", record.getSvcParamValue(SVCBRecord.ALPN).toString());
    assertEquals("h1,h2", record.getSvcParamValue(SVCBRecord.ALPN).toString());
    assertNull(record.getSvcParamValue(1234));
    assertEquals("test.com.\t\t300\tIN\tSVCB\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8", record.toString());
  }

  @Test
  void aliasMode() throws IOException {
    String str = "0 a.b.c.";
    byte[] bytes = stringToWire(str);
    byte[] expected = new byte[] { 0, 0, 1, 'a', 1, 'b', 1, 'c', 0 };
    assertArrayEquals(expected, bytes);
    assertEquals(str, wireToString(bytes));
  }

  @Test
  void serviceModePort() throws IOException {
    String str = "1 . port=8443";
    byte[] bytes = stringToWire(str);
    byte[] expected = new byte[] { 0, 1, 0, 0, 3, 0, 2, 0x20, (byte) 0xFB};
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
    byte[] expected = new byte[] { 0, 1, 0, 0, 1, 0, 6, 2, 'h', '2', 2, 'h', '3'};
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
    String str = "1 . alpn=\"h2\\,h3,h4\"";
    assertEquals("1 . alpn=h2\\,h3,h4", stringToWireToString(str));
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
  void serviceModeEchConfig() throws IOException {
    String str = "1 h3pool. echconfig=1234";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeEchConfigMulti() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 echconfig=1234";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceModeEchConfigOutOfOrder() throws IOException {
    String str = "1 h3pool. echconfig=1234 alpn=h2,h3";
    assertEquals("1 h3pool. alpn=h2,h3 echconfig=1234", stringToWireToString(str));
  }

  @Test
  void serviceModeEchConfigQuoted() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 echconfig=\"1234\"";
    assertEquals("1 h3pool. alpn=h2,h3 echconfig=1234", stringToWireToString(str));
  }

  @Disabled
  @Test
  void serviceModeRelativeDomain() throws IOException {
    String str = "1 h3pool alpn=h2,h3 echconfig=\"1234\"";
    assertEquals("1 h3pool. alpn=h2,h3 echconfig=1234", stringToWireToString(str));
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
    byte[] expected = new byte[] { 0, 5, 0, 0, 4, 0, 8, 4, 5, 6, 7, 8, 9, 1, 2 };
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
    String str = "9 . ipv6hint=2001:2002::1";
    assertEquals("9 . ipv6hint=2001:2002:0:0:0:0:0:1", stringToWireToString(str));
  }

  @Test
  void serviceModeIpv6HintMulti() throws IOException {
    String str = "2 . alpn=h2 ipv6hint=2001:2002::1,2001:2002::2";
    assertEquals("2 . alpn=h2 ipv6hint=2001:2002:0:0:0:0:0:1,2001:2002:0:0:0:0:0:2", stringToWireToString(str));
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
    byte[] expected = new byte[] { 0, 8, 0, 0x5B, (byte) 0xA0, 0, 4, 0, 1, 2, 3 };
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
  void invalidText() {
    String str = "these are all garbage strings that should fail";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void extraQuotesInParamValues() {
    String str = "5 . ipv4hint=\"4.5.6.7\",\"8.9.1.2\"";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void serviceModeWithoutParameters() {
    String str = "1 aliasmode.example.com.";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void aliasModeWithParameters() {
    String str = "0 . alpn=h3";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void zeroLengthAlpnValue() {
    String str = "1 . alpn=";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void unknownKey() {
    String str = "1 . sport=8443";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void portValueTooLarge() {
    String str = "1 . port=84438";
    assertThrows(IllegalArgumentException.class, () -> { stringToWire(str); } );
  }

  @Test
  void zeroLengthPortValue() {
    String str = "1 . port=";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void noDefaultAlpnWithValue() {
    String str = "1 . no-default-alpn=true";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void emptyString() {
    String str = "";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void noParamValues() {
    String str = "1 .";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void svcPriorityTooHigh() {
    String str = "65536 . port=443";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void invalidPortKey() {
    String str = "1 . port<5";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void invalidSvcDomain() {
    String str = "1 fred..harvey port=80";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void duplicateParamKey() {
    String str = "1 . alpn=h2 alpn=h3";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void invalidIpv4Hint() {
    String str = "1 . ipv4hint=2001::1";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void invalidIpv6Hint() {
    String str = "1 . ipv6hint=1.2.3.4";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void negativeSvcPriority() {
    String str = "-1 . port=80";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void svcParamUnknownKeyTooHigh() {
    String str = "65535 . key65536=abcdefg";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
  }

  @Test
  void invalidSvcParamKey() {
    String str = "65535 . keyBlooie=abcdefg";
    assertThrows(TextParseException.class, () -> { stringToWire(str); } );
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

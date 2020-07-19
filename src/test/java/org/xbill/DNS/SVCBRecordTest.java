package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class SVCBRecordTest {
  @Test
  void aliasForm() throws IOException {
    String str = "0 aliasform.example.com.";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormPort() throws IOException {
    String str = "1 . port=8443";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormAlpn() throws IOException {
    String str = "1 . alpn=h3";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormNoDefaultAlpn() throws IOException {
    String str = "1 . no-default-alpn";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormMultiKey() throws IOException {
    String str = "1 . alpn=h3 no-default-alpn";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormIntKey() throws IOException {
    String str = "1 . 1=h3";
    assertEquals("1 . alpn=h3", stringToWireToString(str));
  }

  @Test
  void serviceFormMultiValue() throws IOException {
    String str = "1 . alpn=h2,h3";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormQuotedValue() throws IOException {
    String str = "1 . alpn=\"h2,h3\"";
    assertEquals("1 . alpn=h2,h3", stringToWireToString(str));
  }

  @Test
  void serviceFormQuotedEscapedValue() throws IOException {
    String str = "1 . alpn=\"h2\\,h3,h4\"";
    assertEquals("1 . alpn=h2\\,h3,h4", stringToWireToString(str));
  }

  @Test
  void serviceFormMandatoryAndOutOfOrder() throws IOException {
    String str = "1 . alpn=h3 no-default-alpn mandatory=alpn";
    assertEquals("1 . mandatory=alpn alpn=h3 no-default-alpn", stringToWireToString(str));
  }

  @Test
  void serviceFormEscapedDomain() throws IOException {
    String str = "1 dotty\\.lotty.example.com. no-default-alpn";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormEchConfig() throws IOException {
    String str = "1 h3pool. echconfig=1234";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormEchConfigMulti() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 echconfig=1234";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormEchConfigOutOfOrder() throws IOException {
    String str = "1 h3pool. echconfig=1234 alpn=h2,h3";
    assertEquals("1 h3pool. alpn=h2,h3 echconfig=1234", stringToWireToString(str));
  }

  @Test
  void serviceFormEchConfigQuoted() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 echconfig=\"1234\"";
    assertEquals("1 h3pool. alpn=h2,h3 echconfig=1234", stringToWireToString(str));
  }

  @Disabled
  @Test
  void serviceFormRelativeDomain() throws IOException {
    String str = "1 h3pool alpn=h2,h3 echconfig=\"1234\"";
    assertEquals("1 h3pool. alpn=h2,h3 echconfig=1234", stringToWireToString(str));
  }

  @Test
  void serviceFormIpv4Hint() throws IOException {
    String str = "3 . ipv4hint=4.5.6.7";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormIpv4HintList() throws IOException {
    String str = "5 . ipv4hint=4.5.6.7,8.9.1.2";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormIpv4HintQuoted() throws IOException {
    String str = "5 . ipv4hint=\"4.5.6.7,8.9.1.2\"";
    assertEquals("5 . ipv4hint=4.5.6.7,8.9.1.2", stringToWireToString(str));
  }

  @Test
  void serviceFormIpv4HintMultiKey() throws IOException {
    String str = "7 . alpn=h2 ipv4hint=4.5.6.7";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormIpv6Hint() throws IOException {
    String str = "9 . ipv6hint=2001:2002::1";
    assertEquals("9 . ipv6hint=2001:2002:0:0:0:0:0:1", stringToWireToString(str));
  }

  @Test
  void serviceFormIpv6HintMulti() throws IOException {
    String str = "2 . alpn=h2 ipv6hint=2001:2002::1,2001:2002::2";
    assertEquals("2 . alpn=h2 ipv6hint=2001:2002:0:0:0:0:0:1,2001:2002:0:0:0:0:0:2", stringToWireToString(str));
  }

  @Test
  void serviceFormUnknownKey() throws IOException {
    String str = "6 . key12345=abcdefg\\012";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormUnknownKeyBytes() throws IOException {
    String str = "8 . key23456=\\000\\001\\002\\003";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormUnknownKeyEscapedChars() throws IOException {
    String str = "1 . key29=a\\b\\c";
    assertEquals("1 . key29=abc", stringToWireToString(str));
  }

  @Test
  void serviceFormUnknownKeyEscapedSlash() throws IOException {
    String str = "65535 . key29=a\\\\b\\\\c";
    assertEquals(str, stringToWireToString(str));
  }

  @Test
  void serviceFormUnknownHighKey() throws IOException {
    String str = "65535 . key65535=abcdefg";
    assertEquals(str, stringToWireToString(str));
  }

  private String stringToWireToString(String str) throws IOException {
    Tokenizer t = new Tokenizer(str);
    SVCBRecord record = new SVCBRecord();
    record.rdataFromString(t, null);
    DNSOutput out = new DNSOutput();
    record.rrToWire(out, null, true);
    DNSInput in = new DNSInput(out.toByteArray());
    SVCBRecord record2 = new SVCBRecord();
    record2.rrFromWire(in);
    return record2.rdataToString();
  }
}

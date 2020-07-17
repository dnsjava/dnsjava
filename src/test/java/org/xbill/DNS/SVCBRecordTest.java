package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

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
    assertEquals(str, stringToWireToString(str));
  }

  private String stringToWireToString(String str) throws IOException {
    System.out.println("AWS string: " + str);
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

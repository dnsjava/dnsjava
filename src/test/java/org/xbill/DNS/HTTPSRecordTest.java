package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class HTTPSRecordTest {
  @Test
  void createRecord() throws IOException {
    Name label = Name.fromString("test.com.");
    int svcPriority = 5;
    Name svcDomain = Name.fromString("svc.test.com.");
    HTTPSRecord.ParameterMandatory mandatory = new HTTPSRecord.ParameterMandatory();
    mandatory.fromString("alpn");
    HTTPSRecord.ParameterAlpn alpn = new HTTPSRecord.ParameterAlpn();
    alpn.fromString("h1,h2");
    HTTPSRecord.ParameterIpv4Hint ipv4 = new HTTPSRecord.ParameterIpv4Hint();
    ipv4.fromString("1.2.3.4,5.6.7.8");
    List<HTTPSRecord.ParameterBase> params = Arrays.asList(mandatory, ipv4, alpn);
    HTTPSRecord record = new HTTPSRecord(label, DClass.IN, 300, svcPriority, svcDomain, params);

    assertEquals(Type.HTTPS, record.getType());
    assertEquals(label, record.getName());
    assertEquals(svcPriority, record.getSvcPriority());
    assertEquals(svcDomain, record.getTargetName());
    assertEquals(Arrays.asList(HTTPSRecord.MANDATORY, HTTPSRecord.ALPN, HTTPSRecord.IPV4HINT).toString(), record.getSvcParamKeys().toString());
    assertEquals("alpn", record.getSvcParamValue(HTTPSRecord.MANDATORY).toString());
    assertEquals("h1,h2", record.getSvcParamValue(HTTPSRecord.ALPN).toString());
    assertEquals("h1,h2", record.getSvcParamValue(HTTPSRecord.ALPN).toString());
    assertNull(record.getSvcParamValue(1234));
    assertEquals("test.com.\t\t300\tIN\tHTTPS\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8", record.toString());
  }

  @Test
  void aliasMode() throws IOException {
    String str = "0 a.b.c.";
    byte[] bytes = SVCBRecordTest.stringToWire(str);
    byte[] expected = new byte[] { 0, 0, 1, 'a', 1, 'b', 1, 'c', 0 };
    assertArrayEquals(expected, bytes);
    assertEquals(str, SVCBRecordTest.wireToString(bytes));
  }

  @Test
  void serviceModePort() throws IOException {
    String str = "1 . port=8443";
    byte[] bytes = SVCBRecordTest.stringToWire(str);
    byte[] expected = new byte[] { 0, 1, 0, 0, 3, 0, 2, 0x20, (byte) 0xFB};
    assertArrayEquals(expected, bytes);
    assertEquals(str, SVCBRecordTest.wireToString(bytes));
  }

  @Test
  void serviceModeEchConfigMulti() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 echconfig=1234";
    assertEquals(str, SVCBRecordTest.stringToWireToString(str));
  }

  @Test
  void unknownKey() {
    String str = "1 . sport=8443";
    assertThrows(TextParseException.class, () -> { SVCBRecordTest.stringToWire(str); } );
  }
}

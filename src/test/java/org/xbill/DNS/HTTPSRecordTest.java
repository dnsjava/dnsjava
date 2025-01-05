// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class HTTPSRecordTest {
  @Test
  @SuppressWarnings("deprecation")
  void createParams() throws UnknownHostException, TextParseException {
    List<Integer> mandatoryList = Arrays.asList(HTTPSRecord.ALPN, HTTPSRecord.IPV4HINT);
    HTTPSRecord.ParameterMandatory mandatory = new HTTPSRecord.ParameterMandatory(mandatoryList);
    assertEquals(HTTPSRecord.MANDATORY, mandatory.getKey());
    assertEquals(mandatoryList, mandatory.getValues());

    List<String> alpnList = Arrays.asList("h2", "h3");
    HTTPSRecord.ParameterAlpn alpn = new HTTPSRecord.ParameterAlpn(alpnList);
    assertEquals(HTTPSRecord.ALPN, alpn.getKey());
    assertEquals(alpnList, alpn.getValues());

    HTTPSRecord.ParameterPort port = new HTTPSRecord.ParameterPort(8443);
    assertEquals(HTTPSRecord.PORT, port.getKey());
    assertEquals(8443, port.getPort());

    List<Inet4Address> ipv4List =
        Collections.singletonList((Inet4Address) InetAddress.getByName("1.2.3.4"));
    HTTPSRecord.ParameterIpv4Hint ipv4hint = new HTTPSRecord.ParameterIpv4Hint(ipv4List);
    assertEquals(HTTPSRecord.IPV4HINT, ipv4hint.getKey());
    assertEquals(ipv4List, ipv4hint.getAddresses());

    byte[] data = {'a', 'b', 'c'};
    SVCBBase.ParameterEch ech = new SVCBBase.ParameterEch(data);
    assertEquals(HTTPSRecord.ECH, ech.getKey());
    assertEquals(data, ech.getData());

    HTTPSRecord.ParameterEchConfig echconfig = new HTTPSRecord.ParameterEchConfig(data);
    assertEquals(HTTPSRecord.ECHCONFIG, echconfig.getKey());
    assertEquals(data, echconfig.getData());

    List<Inet6Address> ipv6List =
        Collections.singletonList((Inet6Address) InetAddress.getByName("2001:db8::1"));
    HTTPSRecord.ParameterIpv6Hint ipv6hint = new HTTPSRecord.ParameterIpv6Hint(ipv6List);
    assertEquals(HTTPSRecord.IPV6HINT, ipv6hint.getKey());
    assertEquals(ipv6List, ipv6hint.getAddresses());

    byte[] value = {0, 1, 2, 3};
    HTTPSRecord.ParameterUnknown unknown = new HTTPSRecord.ParameterUnknown(33, value);
    assertEquals(33, unknown.getKey());
    assertEquals(value, unknown.getValue());
  }

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
    HTTPSRecord https = new HTTPSRecord(label, DClass.IN, 300, svcPriority, svcDomain, params);

    assertEquals(Type.HTTPS, https.getType());
    assertEquals(label, https.getName());
    assertEquals(svcPriority, https.getSvcPriority());
    assertEquals(svcDomain, https.getTargetName());
    assertEquals(
        Arrays.asList(HTTPSRecord.MANDATORY, HTTPSRecord.ALPN, HTTPSRecord.IPV4HINT).toString(),
        https.getSvcParamKeys().toString());
    assertEquals("alpn", https.getSvcParamValue(HTTPSRecord.MANDATORY).toString());
    assertEquals("h1,h2", https.getSvcParamValue(HTTPSRecord.ALPN).toString());
    assertEquals("h1,h2", https.getSvcParamValue(HTTPSRecord.ALPN).toString());
    assertNull(https.getSvcParamValue(1234));
    Options.unset("BINDTTL");
    Options.unset("noPrintIN");
    assertEquals(
        "test.com.\t\t300\tIN\tHTTPS\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8",
        https.toString());
  }

  @Test
  void aliasMode() throws IOException {
    String str = "0 a.b.c.";
    byte[] bytes = SVCBRecordTest.stringToWire(str);
    byte[] expected = new byte[] {0, 0, 1, 'a', 1, 'b', 1, 'c', 0};
    assertArrayEquals(expected, bytes);
    assertEquals(str, SVCBRecordTest.wireToString(bytes));
  }

  @Test
  void serviceModePort() throws IOException {
    String str = "1 . port=8443";
    byte[] bytes = SVCBRecordTest.stringToWire(str);
    byte[] expected = new byte[] {0, 1, 0, 0, 3, 0, 2, 0x20, (byte) 0xFB};
    assertArrayEquals(expected, bytes);
    assertEquals(str, SVCBRecordTest.wireToString(bytes));
  }

  @Test
  void serviceModeEchMulti() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 ech=1234";
    assertEquals(str, SVCBRecordTest.stringToWireToString(str));
  }

  @Test
  void unknownKey() {
    String str = "1 . sport=8443";
    assertThrows(TextParseException.class, () -> SVCBRecordTest.stringToWire(str));
  }
}

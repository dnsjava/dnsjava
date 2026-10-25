// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
    assertThat(mandatory.getKey()).isEqualTo(HTTPSRecord.MANDATORY);
    assertThat(mandatory.getValues()).isEqualTo(mandatoryList);

    List<String> alpnList = Arrays.asList("h2", "h3");
    HTTPSRecord.ParameterAlpn alpn = new HTTPSRecord.ParameterAlpn(alpnList);
    assertThat(alpn.getKey()).isEqualTo(HTTPSRecord.ALPN);
    assertThat(alpn.getValues()).isEqualTo(alpnList);

    HTTPSRecord.ParameterPort port = new HTTPSRecord.ParameterPort(8443);
    assertThat(port.getKey()).isEqualTo(HTTPSRecord.PORT);
    assertThat(port.getPort()).isEqualTo(8443);

    List<Inet4Address> ipv4List =
        Collections.singletonList((Inet4Address) InetAddress.getByName("1.2.3.4"));
    HTTPSRecord.ParameterIpv4Hint ipv4hint = new HTTPSRecord.ParameterIpv4Hint(ipv4List);
    assertThat(ipv4hint.getKey()).isEqualTo(HTTPSRecord.IPV4HINT);
    assertThat(ipv4hint.getAddresses()).isEqualTo(ipv4List);

    byte[] data = {'a', 'b', 'c'};
    SVCBBase.ParameterEch ech = new SVCBBase.ParameterEch(data);
    assertThat(ech.getKey()).isEqualTo(HTTPSRecord.ECH);
    assertThat(ech.getData()).isEqualTo(data);

    HTTPSRecord.ParameterEchConfig echconfig = new HTTPSRecord.ParameterEchConfig(data);
    assertThat(echconfig.getKey()).isEqualTo(HTTPSRecord.ECHCONFIG);
    assertThat(echconfig.getData()).isEqualTo(data);

    List<Inet6Address> ipv6List =
        Collections.singletonList((Inet6Address) InetAddress.getByName("2001:db8::1"));
    HTTPSRecord.ParameterIpv6Hint ipv6hint = new HTTPSRecord.ParameterIpv6Hint(ipv6List);
    assertThat(ipv6hint.getKey()).isEqualTo(HTTPSRecord.IPV6HINT);
    assertThat(ipv6hint.getAddresses()).isEqualTo(ipv6List);

    byte[] value = {0, 1, 2, 3};
    HTTPSRecord.ParameterUnknown unknown = new HTTPSRecord.ParameterUnknown(33, value);
    assertThat(unknown.getKey()).isEqualTo(33);
    assertThat(unknown.getValue()).isEqualTo(value);
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

    assertThat(https.getType()).isEqualTo(Type.HTTPS);
    assertThat(https.getName()).isEqualTo(label);
    assertThat(https.getSvcPriority()).isEqualTo(svcPriority);
    assertThat(https.getTargetName()).isEqualTo(svcDomain);
    assertThat(https.getSvcParamKeys())
        .hasToString(
            Arrays.asList(HTTPSRecord.MANDATORY, HTTPSRecord.ALPN, HTTPSRecord.IPV4HINT)
                .toString());
    assertThat(https.getSvcParamValue(HTTPSRecord.MANDATORY)).hasToString("alpn");
    assertThat(https.getSvcParamValue(HTTPSRecord.ALPN)).hasToString("h1,h2");
    assertThat(https.getSvcParamValue(HTTPSRecord.ALPN)).hasToString("h1,h2");
    assertThat(https.getSvcParamValue(1234)).isNull();
    Options.unset("BINDTTL");
    Options.unset("noPrintIN");
    assertThat(https)
        .hasToString(
            "test.com.\t\t300\tIN\tHTTPS\t5 svc.test.com. mandatory=alpn alpn=h1,h2 ipv4hint=1.2.3.4,5.6.7.8");
  }

  @Test
  void aliasMode() throws IOException {
    String str = "0 a.b.c.";
    byte[] bytes = SVCBRecordTest.stringToWire(str);
    byte[] expected = {0, 0, 1, 'a', 1, 'b', 1, 'c', 0};
    assertThat(bytes).containsExactly(expected);
    assertThat(SVCBRecordTest.wireToString(bytes)).isEqualTo(str);
  }

  @Test
  void serviceModePort() throws IOException {
    String str = "1 . port=8443";
    byte[] bytes = SVCBRecordTest.stringToWire(str);
    byte[] expected = {0, 1, 0, 0, 3, 0, 2, 0x20, (byte) 0xFB};
    assertThat(bytes).containsExactly(expected);
    assertThat(SVCBRecordTest.wireToString(bytes)).isEqualTo(str);
  }

  @Test
  void serviceModeEchMulti() throws IOException {
    String str = "1 h3pool. alpn=h2,h3 ech=1234";
    assertThat(SVCBRecordTest.stringToWireToString(str)).isEqualTo(str);
  }

  @Test
  void unknownKey() {
    String str = "1 . sport=8443";
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> SVCBRecordTest.stringToWire(str));
  }
}

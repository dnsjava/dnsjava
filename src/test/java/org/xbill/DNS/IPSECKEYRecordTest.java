// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class IPSECKEYRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    IPSECKEYRecord ipsecKey = new IPSECKEYRecord();
    assertEquals(0, ipsecKey.getPrecedence());
    assertEquals(0, ipsecKey.getGatewayType());
    assertEquals(0, ipsecKey.getAlgorithmType());
    assertNull(ipsecKey.getGateway());
    assertNull(ipsecKey.getKey());
  }

  @Test
  void ctor_8arg() {
    IPSECKEYRecord ipsecKey =
        new IPSECKEYRecord(
            n,
            DClass.IN,
            0,
            1,
            IPSECKEYRecord.Gateway.Name,
            IPSECKEYRecord.Algorithm.DSA,
            n,
            "".getBytes());
    assertEquals(1, ipsecKey.getPrecedence());
    assertEquals(IPSECKEYRecord.Gateway.Name, ipsecKey.getGatewayType());
    assertEquals(IPSECKEYRecord.Algorithm.DSA, ipsecKey.getAlgorithmType());
    assertEquals(n, ipsecKey.getGateway());
    assertEquals(0, ipsecKey.getKey().length);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("10 0 2 . CAFEBABE");
    IPSECKEYRecord ipseckey = new IPSECKEYRecord();
    ipseckey.rdataFromString(t, null);
    assertEquals(10, ipseckey.getPrecedence());
    assertEquals(IPSECKEYRecord.Gateway.None, ipseckey.getGatewayType());
    assertEquals(IPSECKEYRecord.Algorithm.RSA, ipseckey.getAlgorithmType());
    assertNull(ipseckey.getGateway());
    assertEquals(6, ipseckey.getKey().length);
    ipseckey = new IPSECKEYRecord();
    t = new Tokenizer("( 10 1 2 192.0.2.3 CAFEBABE )");
    ipseckey.rdataFromString(t, null);
    assertEquals(1, ipseckey.getGatewayType());
    assertInstanceOf(InetAddress.class, ipseckey.getGateway());
    ipseckey = new IPSECKEYRecord();
    t = new Tokenizer("10 2 2 2001:0DB8:0:8002::2000:1 CAFEBABE");
    ipseckey.rdataFromString(t, null);
    assertEquals(2, ipseckey.getGatewayType());
    assertInstanceOf(InetAddress.class, ipseckey.getGateway());
    ipseckey = new IPSECKEYRecord();
    t = new Tokenizer("10 3 2 mygateway.example.com. CAFEBABE");
    ipseckey.rdataFromString(t, null);
    assertEquals(3, ipseckey.getGatewayType());
    assertEquals(Name.fromConstantString("mygateway.example.com."), ipseckey.getGateway());
  }
}

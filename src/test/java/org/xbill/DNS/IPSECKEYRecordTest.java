// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

class IPSECKEYRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    IPSECKEYRecord ipsecKey = new IPSECKEYRecord();
    assertThat(ipsecKey.getPrecedence()).isZero();
    assertThat(ipsecKey.getGatewayType()).isZero();
    assertThat(ipsecKey.getAlgorithmType()).isZero();
    assertThat(ipsecKey.getGateway()).isNull();
    assertThat(ipsecKey.getKey()).isNull();
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
    assertThat(ipsecKey.getPrecedence()).isOne();
    assertThat(ipsecKey.getGatewayType()).isEqualTo(IPSECKEYRecord.Gateway.Name);
    assertThat(ipsecKey.getAlgorithmType()).isEqualTo(IPSECKEYRecord.Algorithm.DSA);
    assertThat(ipsecKey.getGateway()).isEqualTo(n);
    assertThat(ipsecKey.getKey()).isEmpty();
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("10 0 2 . CAFEBABE");
    IPSECKEYRecord ipseckey = new IPSECKEYRecord();
    ipseckey.rdataFromString(t, null);
    assertThat(ipseckey.getPrecedence()).isEqualTo(10);
    assertThat(ipseckey.getGatewayType()).isEqualTo(IPSECKEYRecord.Gateway.None);
    assertThat(ipseckey.getAlgorithmType()).isEqualTo(IPSECKEYRecord.Algorithm.RSA);
    assertThat(ipseckey.getGateway()).isNull();
    assertThat(ipseckey.getKey()).hasSize(6);
    ipseckey = new IPSECKEYRecord();
    t = new Tokenizer("( 10 1 2 192.0.2.3 CAFEBABE )");
    ipseckey.rdataFromString(t, null);
    assertThat(ipseckey.getGatewayType()).isOne();
    assertThat(ipseckey.getGateway()).isInstanceOf(InetAddress.class);
    ipseckey = new IPSECKEYRecord();
    t = new Tokenizer("10 2 2 2001:0DB8:0:8002::2000:1 CAFEBABE");
    ipseckey.rdataFromString(t, null);
    assertThat(ipseckey.getGatewayType()).isEqualTo(2);
    assertThat(ipseckey.getGateway()).isInstanceOf(InetAddress.class);
    ipseckey = new IPSECKEYRecord();
    t = new Tokenizer("10 3 2 mygateway.example.com. CAFEBABE");
    ipseckey.rdataFromString(t, null);
    assertThat(ipseckey.getGatewayType()).isEqualTo(3);
    assertThat(ipseckey.getGateway()).isEqualTo(Name.fromConstantString("mygateway.example.com."));
  }

  @Test
  void roundtripIPv6MappedIPv4() throws IOException {
    String addressString = "0:0:0:0:0:ffff:192.0.2.1";
    InetAddress address = Address.getByAddress(addressString);
    String rdata = "10 2 2 " + addressString + " AQID";
    IPSECKEYRecord r = new IPSECKEYRecord();
    r.rdataFromString(new Tokenizer(rdata), Name.root);
    assertThat(r.rdataToString()).isEqualTo(rdata);
    assertThat(r.getGatewayType()).isEqualTo(IPSECKEYRecord.Gateway.IPv6);
    assertThat(r.getGateway()).isInstanceOf(InetAddress.class).isEqualTo(address);

    DNSOutput out = new DNSOutput();
    r.rrToWire(out, null, false);
    r = new IPSECKEYRecord();
    r.rrFromWire(new DNSInput(out.toByteArray()));
    assertThat(r.rdataToString()).isEqualTo(rdata);
    assertThat(r.getGatewayType()).isEqualTo(IPSECKEYRecord.Gateway.IPv6);
    assertThat(r.getGateway()).isInstanceOf(InetAddress.class).isEqualTo(address);
  }

  @Test
  void ctorAllowsIPv6MappedIPv4() throws IOException {
    String addressString = "0:0:0:0:0:ffff:192.0.2.1";
    InetAddress address = Address.getByAddress(addressString);
    IPSECKEYRecord r =
        new IPSECKEYRecord(
            n,
            DClass.IN,
            0,
            10,
            IPSECKEYRecord.Gateway.IPv6,
            IPSECKEYRecord.Algorithm.RSA,
            address,
            base64.fromString("AQID"));
    assertThat(r.getGatewayType()).isEqualTo(IPSECKEYRecord.Gateway.IPv6);
    assertThat(r.getGateway()).isInstanceOf(InetAddress.class).isEqualTo(address);
    assertThat(r.rdataToString()).isEqualTo("10 2 2 " + addressString + " AQID");
  }
}

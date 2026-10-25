// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
class DnssecDsaTest {
  private final Name exampleNet = Name.fromConstantString("example.net.");

  @Test
  void testDSA_sign() throws Exception {
    KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
    keygen.initialize(1024);
    KeyPair pair = keygen.generateKeyPair();
    PrivateKey privateKey = pair.getPrivate();

    DNSKEYRecord dnskey =
        new DNSKEYRecord(
            exampleNet, DClass.IN, 3600, 257, 3, DNSSEC.Algorithm.DSA, pair.getPublic());
    DNSKEYRecord dnskey2 =
        (DNSKEYRecord) Record.fromWire(dnskey.toWire(Section.ANSWER), Section.ANSWER);
    assertThat(dnskey2.getPublicKey()).isEqualTo(dnskey.getPublicKey());
    assertThat(dnskey2).hasSameHashCodeAs(dnskey).isEqualTo(dnskey);
    ARecord a =
        new ARecord(
            Name.fromConstantString("www.example.net."),
            DClass.IN,
            3600,
            InetAddress.getByName("192.0.2.1"));
    RRset set = new RRset(a);
    RRSIGRecord rrsig =
        DNSSEC.sign(
            set,
            dnskey,
            privateKey,
            Instant.ofEpochSecond(1281607479),
            Instant.ofEpochSecond(1284026679));
    assertThat(rrsig).isNotNull();

    // verify, but we cannot validate the actual signature as it contains a random value
    DNSSEC.verify(set, rrsig, dnskey, Instant.ofEpochSecond(1281607480));
    assertThat(rrsig.signature).hasSize(41);
  }
}

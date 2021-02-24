// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DNSSEC.DNSSECException;

public class DNSSECWithBCProviderTest {

  private static final String KEY_ALGORITHM = "RSA";
  int algorithm = Algorithm.RSASHA1;
  String bcJCAProvider = "BC";
  byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();
  private Name exampleCom = Name.fromConstantString("example.com.");

  @BeforeAll
  static void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void testSignWithDNSSECAndBCProvider() throws Exception {

    // generate a signature
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, bcJCAProvider);
    keyPairGenerator.initialize(512);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    byte[] signature =
        DNSSEC.sign(keyPair.getPrivate(), keyPair.getPublic(), algorithm, toSign, bcJCAProvider);
    assertNotNull(signature);

    // verify the signature
    Signature verifier = Signature.getInstance(DNSSEC.algString(algorithm), bcJCAProvider);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(toSign);
    boolean verify = verifier.verify(signature);
    assertTrue(verify);
  }

  @Test
  void testEdDSA25519_DNSKEY() throws IOException, DNSSECException {
    String rrString = "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(exampleCom, Type.DNSKEY, DClass.IN, 3600, rrString, Name.root);
    assertEquals(Algorithm.ED25519, dnskey.getAlgorithm());
    assertEquals("Ed25519", dnskey.getPublicKey().getAlgorithm());
    DNSKEYRecord dnskey2 =
        new DNSKEYRecord(exampleCom, DClass.IN, 3600, 257, 3, 15, dnskey.getPublicKey());
    assertEquals(rrString, dnskey2.rrToString());
  }

  @Test
  void testEdDSA25519_DS() throws IOException {
    DSRecord ds =
        (DSRecord)
            Record.fromString(
                exampleCom,
                Type.DS,
                DClass.IN,
                3600,
                "3613 15 2 3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b",
                Name.root);
    assertEquals(Algorithm.ED25519, ds.getAlgorithm());
  }

  @Test
  void testEdDSA448_DNSKEY() throws IOException, DNSSECException {
    String rrString =
        "257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA";
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(exampleCom, Type.DNSKEY, DClass.IN, 3600, rrString, Name.root);
    assertEquals(Algorithm.ED448, dnskey.getAlgorithm());
    assertEquals("Ed448", dnskey.getPublicKey().getAlgorithm());
    DNSKEYRecord dnskey2 =
        new DNSKEYRecord(exampleCom, DClass.IN, 3600, 257, 3, 16, dnskey.getPublicKey());
    assertEquals(rrString, dnskey2.rrToString());
  }

  @Test
  void testEdDSA448_DS() throws IOException {
    DSRecord ds =
        (DSRecord)
            Record.fromString(
                exampleCom,
                Type.DS,
                DClass.IN,
                3600,
                "9713 16 2 6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7",
                Name.root);
    assertEquals(Algorithm.ED448, ds.getAlgorithm());
  }

  @Test
  void testEdDSA25519_verify() throws IOException, DNSSECException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                exampleCom,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
                Name.root);

    try (Master m =
        new Master(
            new ByteArrayInputStream(
                ("example.com. 3600 IN MX 10 mail.example.com.\n"
                        + "example.com. 3600 IN RRSIG MX 15 2 3600 (\n"
                        + "             1440021600 1438207200 3613 example.com. (\n"
                        + "             oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f\n"
                        + "             x8A4M3e23mRZ9VrbpMngwcrqNAg== )")
                    .getBytes(StandardCharsets.US_ASCII)))) {
      RRset set = new RRset();
      Record r;
      while ((r = m.nextRecord()) != null) {
        set.addRR(r);
      }
      DNSSEC.verify(set, set.sigs().get(0), dnskey, Instant.parse("2015-08-19T22:00:00Z"));
    }
  }
}

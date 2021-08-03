// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
public class DnssecEdDsaTest {
  private final Name exampleCom = Name.fromConstantString("example.com.");

  @BeforeAll
  static void beforeAll() {
    if (Integer.getInteger("java.specification.version", 8) < 15) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @AfterAll
  static void afterAll() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=", // first byte > 128
        "G5u2cJRUarlrz2vskaTty+WpC8gZvSGXj9nBfecHDXk=" // first byte < 128
      })
  void testEdDSA25519_DNSKEY(String key) throws IOException, DNSSEC.DNSSECException {
    String rrString = "257 3 15 " + key;
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(exampleCom, Type.DNSKEY, DClass.IN, 3600, rrString, Name.root);
    assertEquals(DNSSEC.Algorithm.ED25519, dnskey.getAlgorithm());
    // As of Java 15, EdDSA is natively supported
    String expected =
        dnskey.getPublicKey().getClass().getName().toLowerCase().contains("bouncycastle")
            ? "Ed25519"
            : "EdDSA";
    assertEquals(expected, dnskey.getPublicKey().getAlgorithm());
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
    assertEquals(DNSSEC.Algorithm.ED25519, ds.getAlgorithm());
  }

  @Test
  void testEdDSA448_DNSKEY() throws IOException, DNSSEC.DNSSECException {
    String rrString =
        "257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA";
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(exampleCom, Type.DNSKEY, DClass.IN, 3600, rrString, Name.root);
    assertEquals(DNSSEC.Algorithm.ED448, dnskey.getAlgorithm());
    // As of Java 15, EdDSA is natively supported
    String expected =
        dnskey.getPublicKey().getClass().getName().toLowerCase().contains("bouncycastle")
            ? "Ed448"
            : "EdDSA";
    assertEquals(expected, dnskey.getPublicKey().getAlgorithm());
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
    assertEquals(DNSSEC.Algorithm.ED448, ds.getAlgorithm());
  }

  @Test
  void testEdDSA25519_verify() throws IOException, DNSSEC.DNSSECException {
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

  @Test
  void testEdDSA25519_sign() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
    byte[] privateRaw = Base64.getDecoder().decode("ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=");
    PrivateKeyInfo privateKeyInfo =
        new PrivateKeyInfo(
            new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
            new DEROctetString(privateRaw));
    PrivateKey privateKey =
        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                exampleCom,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
                Name.root);
    MXRecord mx =
        new MXRecord(exampleCom, DClass.IN, 3600, 10, Name.fromConstantString("mail.example.com."));
    RRset set = new RRset(mx);
    RRSIGRecord signature =
        DNSSEC.sign(
            set,
            dnskey,
            privateKey,
            Instant.ofEpochSecond(1438207200),
            Instant.ofEpochSecond(1440021600));
    assertNotNull(signature);

    // verify the signature
    DNSSEC.verify(set, signature, dnskey, Instant.ofEpochSecond(1438207201));
    assertArrayEquals(
        Base64.getDecoder()
            .decode(
                "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg=="),
        signature.signature);
  }

  @Test
  void testEdDSA448_sign() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
    byte[] privateRaw =
        Base64.getDecoder()
            .decode("xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA");
    PrivateKeyInfo privateKeyInfo =
        new PrivateKeyInfo(
            new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448),
            new DEROctetString(privateRaw));
    PrivateKey privateKey =
        keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                exampleCom,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA",
                Name.root);
    MXRecord mx =
        new MXRecord(exampleCom, DClass.IN, 3600, 10, Name.fromConstantString("mail.example.com."));
    RRset set = new RRset(mx);
    RRSIGRecord signature =
        DNSSEC.sign(
            set,
            dnskey,
            privateKey,
            Instant.ofEpochSecond(1438207200),
            Instant.ofEpochSecond(1440021600));
    assertNotNull(signature);

    // verify the signature
    DNSSEC.verify(set, signature, dnskey, Instant.ofEpochSecond(1438207201));
    assertArrayEquals(
        Base64.getDecoder()
            .decode(
                "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA"),
        signature.signature);
  }
}

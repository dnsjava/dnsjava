// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.ECPrivateKeySpec;
import java.time.Instant;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@Slf4j
class DnssecEcDsaTest {
  private final Name exampleNet = Name.fromConstantString("example.net.");

  @BeforeAll
  static void beforeAll() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @AfterAll
  static void afterAll() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
  }

  @Test
  void testEcDSA_P256_sign() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
    byte[] privateRaw = Base64.getDecoder().decode("GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=");
    BigInteger s = new BigInteger(privateRaw);

    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
    ECNamedCurveSpec params =
        new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN());
    ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                exampleNet,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
                Name.root);
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
    assertNotNull(rrsig);

    // verify, but we cannot validate the actual signature as it contains a random value
    DNSSEC.verify(set, rrsig, dnskey, Instant.ofEpochSecond(1281607480));
    assertEquals(64, rrsig.signature.length);
  }

  @Test
  void testEcDSA_P384_sign() throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
    byte[] privateRaw =
        Base64.getDecoder()
            .decode("WURgWHCcYIYUPWgeLmiPY2DJJk02vgrmTfitxgqcL4vwW7BOrbawVmVe0d9V94SR");
    BigInteger s = new BigInteger(privateRaw);

    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp384r1");
    ECNamedCurveSpec params =
        new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN());
    ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
    PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                exampleNet,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
                Name.root);
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
            Instant.ofEpochSecond(1281608425),
            Instant.ofEpochSecond(1284027625));
    assertNotNull(rrsig);

    // verify, but we cannot validate the actual signature as it contains a random value
    DNSSEC.verify(set, rrsig, dnskey, Instant.ofEpochSecond(1281608426));
    assertEquals(96, rrsig.signature.length);
  }
}

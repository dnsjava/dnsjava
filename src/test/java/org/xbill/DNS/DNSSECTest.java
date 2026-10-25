// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DNSSEC.KeyMismatchException;
import org.xbill.DNS.DNSSEC.SignatureExpiredException;
import org.xbill.DNS.DNSSEC.SignatureNotYetValidException;

class DNSSECTest {
  private final TXTRecord txt = new TXTRecord(Name.root, DClass.IN, 3600, "test");

  @Test
  void testECDSALeadingZeroUndersize() throws IOException, DNSSECException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 13 HgcQzDrxDm641ASGyEF0MXrjDji4XDnWzjrY9VoIn5GfAvHpuqI2W8yihplAz6C/56Zxq1XbAHjLZATfhZFmaA==",
                Name.root);
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600,
                "TXT 13 0 3600 19700101000003 19700101000000 46271 . dRwMEthIeGiucMcEcDmwixM8/LZcZ+W6lMM0KDSY5rwAGrm1j7tS/VU6xs+rpD5dSRmBYosinkWD6Jk3zRmyBQ==",
                Name.root);

    RRset rrset = new RRset();
    rrset.addRR(txt);
    rrset.addRR(rrsig);
    DNSSEC.verify(rrset, rrsig, dnskey, Instant.ofEpochMilli(60));
  }

  @Test
  void testECDSALeadingZeroOversize() throws IOException, DNSSECException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 13 OYt2tO1n75q/Wb6CglqPVrU22f02clZehWamgXc9ZGPhVMAerzPR9/bhf1XxtC3xAR9riVuGh9CEPVvmiNqukQ==",
                Name.root);
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600,
                "TXT 13 0 3600 19700101000003 19700101000000 25719 . m6sD/b0ZbfBXsQruhq5dYTnHGaA+PRTL5Y1W36rMdnGBb7eOJRRzDS5Wk5hZlrS4RUKQ/tKMCn7lsl9fn4U2lw==",
                Name.root);

    RRset rrset = new RRset();
    rrset.addRR(txt);
    rrset.addRR(rrsig);
    DNSSEC.verify(rrset, rrsig, dnskey, Instant.ofEpochMilli(60));
  }

  @Test
  void testDSALeadingZeroUndersize() throws DNSSECException, IOException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 3 AJYu3cw2nLqOuyYO5rahJtk0bjjF/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9xD7nN1kuF2eEcbJ6nPRO6RpJxRR9samq8kTwWkNNZIaTHS0UJxueNQMLcf1z2heQabMuKTVjDhwgYjVNDaIKbEFuUL55TKRAt3Xr7t5zCMLaujMvqNHOzCFEusXN5mXjJqAj8J0l4B4tbL7M4iIFZeXJDXGCEcsBbNrVAfFnlOO06B6dkB8L",
                Name.root);
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600L,
                "TXT 3 0 3600 19700101000003 19700101000000 36714 . AAAycZeIdBGB7vjlFzd5+ZgV8IxGRLpLierdV1KO4SGIy707hKUXJRc=",
                Name.root);

    RRset set = new RRset();
    set.addRR(txt);
    set.addRR(rrsig);
    DNSSEC.verify(set, rrsig, dnskey, Instant.ofEpochMilli(60));
  }

  @Test
  void testDSALeadingZeroOversize() throws DNSSECException, IOException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 3 AJYu3cw2nLqOuyYO5rahJtk0bjjF/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9xD7nN1kuF2eEcbJ6nPRO6RpJxRR9samq8kTwWkNNZIaTHS0UJxueNQMLcf1z2heQabMuKTVjDhwgYjVNDaIKbEFuUL55TKQflphJYUXcb2M3wKNGoXP7NufzhfVaDtiS44waWjC8IN98Ab+SPPfM4+xgTsgzWt8KvzL8hhqSW+4+5zjiQ6UG",
                Name.root);
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600L,
                "TXT 3 0 3600 19700101000003 19700101000000 57407 . AIh8Bp0EFNszs3cB0gNatjWy8tBrgUAUe1gTHkVsm1pva1GYWOW/FbA=",
                Name.root);

    RRset set = new RRset();
    set.addRR(txt);
    set.addRR(rrsig);
    DNSSEC.verify(set, rrsig, dnskey, Instant.ofEpochMilli(60));
  }

  @Test
  void testDigestRrsetOrdering() {
    Name name = Name.fromConstantString("a.");
    Record a1 = new CNAMERecord(name, DClass.IN, 60, Name.fromConstantString("a.b.c."));
    Record a2 = new CNAMERecord(name, DClass.IN, 60, Name.fromConstantString("aa.bb.cc."));

    RRSIGRecord s1 =
        new RRSIGRecord(
            name,
            DClass.IN,
            60,
            Type.CNAME,
            0xF,
            0x60,
            Instant.now(),
            Instant.now(),
            0xA,
            name,
            new byte[] {0xa, 0x0});
    RRSIGRecord s2 =
        new RRSIGRecord(
            name,
            DClass.IN,
            60,
            Type.CNAME,
            0xF,
            0x60,
            Instant.now(),
            Instant.now(),
            0xB,
            name,
            new byte[] {0x0, 0xa});
    RRset rrset = new RRset();
    rrset.addRR(a2);
    rrset.addRR(a1);
    rrset.addRR(s1);
    rrset.addRR(s2);
    assertThat(DNSSEC.digestRRset(s1, rrset)).containsExactly(DNSSEC.digestRRset(s1, rrset));
  }

  @ParameterizedTest
  @MethodSource("testAlgorithmMnemonicSources")
  void testAlgorithmMnemonic(int algId, String algName) {
    assertThat(DNSSEC.Algorithm.string(algId)).isEqualTo(algName);
    assertThat(DNSSEC.Algorithm.value("UNKNOWN_ALG")).isEqualTo(-1);
  }

  private static Stream<Arguments> testAlgorithmMnemonicSources() {
    return Stream.of(
        Arguments.of(DNSSEC.Algorithm.DELETE, "DELETE"),
        Arguments.of(DNSSEC.Algorithm.DH, "DH"),
        Arguments.of(DNSSEC.Algorithm.DSA, "DSA"),
        Arguments.of(DNSSEC.Algorithm.RSASHA1, "RSASHA1"),
        Arguments.of(DNSSEC.Algorithm.DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1"),
        Arguments.of(DNSSEC.Algorithm.RSA_NSEC3_SHA1, "RSASHA1-NSEC3-SHA1"),
        Arguments.of(DNSSEC.Algorithm.RSASHA256, "RSASHA256"),
        Arguments.of(DNSSEC.Algorithm.RSASHA512, "RSASHA512"),
        Arguments.of(DNSSEC.Algorithm.ECC_GOST, "ECC-GOST"),
        Arguments.of(DNSSEC.Algorithm.ECDSAP256SHA256, "ECDSAP256SHA256"),
        Arguments.of(DNSSEC.Algorithm.ECDSAP384SHA384, "ECDSAP384SHA384"),
        Arguments.of(DNSSEC.Algorithm.ED25519, "ED25519"),
        Arguments.of(DNSSEC.Algorithm.ED448, "ED448"),
        Arguments.of(DNSSEC.Algorithm.SM2SM3, "SM2SM3"),
        Arguments.of(DNSSEC.Algorithm.ECC_GOST12, "ECC-GOST12"),
        Arguments.of(DNSSEC.Algorithm.INDIRECT, "INDIRECT"),
        Arguments.of(DNSSEC.Algorithm.PRIVATEDNS, "PRIVATEDNS"),
        Arguments.of(DNSSEC.Algorithm.PRIVATEOID, "PRIVATEOID"));
  }

  @ParameterizedTest
  @MethodSource("testDigestMnemonicSources")
  void testDigestMnemonic(int algId, String algName) {
    assertThat(DNSSEC.Digest.string(algId)).isEqualTo(algName);
    assertThat(DNSSEC.Digest.value(algName)).isEqualTo(algId);
  }

  private static Stream<Arguments> testDigestMnemonicSources() {
    return Stream.of(
        Arguments.of(DNSSEC.Digest.SHA1, "SHA-1"),
        Arguments.of(DNSSEC.Digest.SHA256, "SHA-256"),
        Arguments.of(DNSSEC.Digest.GOST3411, "GOST R 34.11-94"),
        Arguments.of(DNSSEC.Digest.SHA384, "SHA-384"),
        Arguments.of(DNSSEC.Digest.GOST3411_12, "GOST12"),
        Arguments.of(DNSSEC.Digest.SM3, "SM3"));
  }

  @Test
  void testGenerateDSDigest() throws TextParseException {
    DNSKEYRecord dnskey =
        new DNSKEYRecord(
            Name.fromString("example.com."),
            DClass.IN,
            3600,
            DNSKEYRecord.Flags.ZONE_KEY,
            DNSKEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.DSA,
            new byte[] {1, 2, 3, 4});
    byte[] digest = DNSSEC.generateDSDigest(dnskey, DNSSEC.Digest.SHA256);
    assertThat(digest).isNotNull().hasSize(DNSSEC.Digest.algLength(DNSSEC.Algorithm.DSA));
  }

  @Test
  void testSignatureExpired() throws IOException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 13 HgcQzDrxDm641ASGyEF0MXrjDji4XDnWzjrY9VoIn5GfAvHpuqI2W8yihplAz6C/56Zxq1XbAHjLZATfhZFmaA==",
                Name.root);
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600,
                "TXT 13 0 3600 19700101000003 19700101000000 46271 . dRwMEthIeGiucMcEcDmwixM8/LZcZ+W6lMM0KDSY5rwAGrm1j7tS/VU6xs+rpD5dSRmBYosinkWD6Jk3zRmyBQ==",
                Name.root);

    RRset rrset = new RRset();
    rrset.addRR(txt);
    rrset.addRR(rrsig);

    // Expired: now (10s) > expiration (3s)
    assertThatExceptionOfType(SignatureExpiredException.class)
        .isThrownBy(() -> DNSSEC.verify(rrset, rrsig, dnskey, Instant.ofEpochSecond(10)));
  }

  @Test
  void testSignatureNotYetValid() throws IOException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 13 HgcQzDrxDm641ASGyEF0MXrjDji4XDnWzjrY9VoIn5GfAvHpuqI2W8yihplAz6C/56Zxq1XbAHjLZATfhZFmaA==",
                Name.root);
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600,
                "TXT 13 0 3600 19700101000003 19700101000001 46271 . dRwMEthIeGiucMcEcDmwixM8/LZcZ+W6lMM0KDSY5rwAGrm1j7tS/VU6xs+rpD5dSRmBYosinkWD6Jk3zRmyBQ==",
                Name.root);

    RRset rrset = new RRset();
    rrset.addRR(txt);
    rrset.addRR(rrsig);

    // Not yet valid: now (0s) < inception (1s)
    assertThatExceptionOfType(SignatureNotYetValidException.class)
        .isThrownBy(() -> DNSSEC.verify(rrset, rrsig, dnskey, Instant.ofEpochSecond(0)));
  }

  @Test
  void testKeyMismatch() throws IOException {
    DNSKEYRecord dnskey =
        (DNSKEYRecord)
            Record.fromString(
                Name.root,
                Type.DNSKEY,
                DClass.IN,
                3600,
                "256 3 13 HgcQzDrxDm641ASGyEF0MXrjDji4XDnWzjrY9VoIn5GfAvHpuqI2W8yihplAz6C/56Zxq1XbAHjLZATfhZFmaA==",
                Name.root);
    // RRSIG with different key tag (46272 instead of 46271)
    RRSIGRecord rrsig =
        (RRSIGRecord)
            Record.fromString(
                Name.root,
                Type.RRSIG,
                DClass.IN,
                3600,
                "TXT 13 0 3600 19700101000003 19700101000000 46272 . dRwMEthIeGiucMcEcDmwixM8/LZcZ+W6lMM0KDSY5rwAGrm1j7tS/VU6xs+rpD5dSRmBYosinkWD6Jk3zRmyBQ==",
                Name.root);

    RRset rrset = new RRset();
    rrset.addRR(txt);
    rrset.addRR(rrsig);

    assertThatExceptionOfType(KeyMismatchException.class)
        .isThrownBy(() -> DNSSEC.verify(rrset, rrsig, dnskey, Instant.ofEpochMilli(60)));
  }

  @Test
  void testSignAndVerify() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    Name name = Name.fromString("example.com.");
    DNSKEYRecord dnskey =
        new DNSKEYRecord(
            name,
            DClass.IN,
            3600,
            DNSKEYRecord.Flags.ZONE_KEY,
            DNSKEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.RSASHA256,
            kp.getPublic());

    RRset rrset = new RRset();
    rrset.addRR(new TXTRecord(name, DClass.IN, 3600, "hello"));

    Instant now = Instant.now();
    Instant inception = now.minus(1, ChronoUnit.HOURS);
    Instant expiration = now.plus(1, ChronoUnit.HOURS);

    RRSIGRecord rrsig = DNSSEC.sign(rrset, dnskey, kp.getPrivate(), inception, expiration);
    assertThat(rrsig).isNotNull();
    assertThat(rrsig.getFootprint()).isEqualTo(dnskey.getFootprint());

    rrset.addRR(rrsig);
    DNSSEC.verify(rrset, rrsig, dnskey, now);
  }

  @Test
  void testSignAndVerifyMessage() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    Name name = Name.fromString("example.com.");
    KEYRecord keyRecord =
        new KEYRecord(
            name,
            DClass.IN,
            3600,
            KEYRecord.Flags.ZONE,
            KEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.RSASHA256,
            kp.getPublic());

    Message msg = new Message();
    msg.addRecord(new TXTRecord(name, DClass.IN, 3600, "message test"), Section.ANSWER);

    Instant now = Instant.now();
    Instant inception = now.minus(1, ChronoUnit.HOURS);
    Instant expiration = now.plus(1, ChronoUnit.HOURS);

    SIGRecord sig =
        DNSSEC.signMessage(msg, null, keyRecord, kp.getPrivate(), inception, expiration);
    assertThat(sig).isNotNull();

    msg.addRecord(sig, Section.ADDITIONAL);
    byte[] wire = msg.toWire();
    Message msg2 = new Message(wire);

    DNSSEC.verifyMessage(msg2, wire, sig, null, keyRecord, now);
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;

public class DnsSecVerifierTests {
  private final DnsSecVerifier verifier = new DnsSecVerifier(new ValUtils());
  private final DNSKEYRecord key;
  private final KeyEntry keyEntry;
  private final RRset unsigned;
  private final RRset signed;
  private final RRset multiSigned;
  private static final int NUM_RRSIGS = 5;

  DnsSecVerifierTests() throws NoSuchAlgorithmException, DNSSEC.DNSSECException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair rsaKeyPair = kpg.generateKeyPair();
    key =
        new DNSKEYRecord(
            Name.root,
            DClass.IN,
            3600,
            DNSKEYRecord.Flags.ZONE_KEY,
            DNSKEYRecord.Protocol.DNSSEC,
            DNSSEC.Algorithm.RSASHA256,
            rsaKeyPair.getPublic());
    keyEntry = KeyEntry.newKeyEntry(new SRRset(key));
    unsigned = new RRset(new ARecord(Name.root, DClass.IN, 3600, new byte[4]));
    signed = new RRset(new ARecord(Name.root, DClass.IN, 3600, new byte[4]));
    Instant inception = Instant.ofEpochSecond(3600);
    Instant expiration = Instant.ofEpochSecond(7200);
    signed.addRR(DNSSEC.sign(signed, key, rsaKeyPair.getPrivate(), inception, expiration));

    multiSigned = new RRset(new ARecord(Name.root, DClass.IN, 3600, new byte[4]));
    for (int i = 0; i < NUM_RRSIGS; i++) {
      multiSigned.addRR(
          DNSSEC.sign(
              signed,
              key,
              rsaKeyPair.getPrivate(),
              inception.plusSeconds(i),
              expiration.plusSeconds(1)));
    }
  }

  @BeforeEach
  void beforeEach() {
    verifier.init(new Properties());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void validateUnsigned(boolean asSet) {
    JustifiedSecStatus status;
    if (asSet) {
      status = verifier.verify(new SRRset(unsigned), keyEntry, Instant.ofEpochSecond(5400));
    } else {
      status = verifier.verify(unsigned, key, Instant.ofEpochSecond(5400));
    }

    assertThat(status.status).isEqualTo(SecurityStatus.BOGUS);
    assertThat(status.edeReason).isEqualTo(ExtendedErrorCodeOption.RRSIGS_MISSING);
    assertThat(status.reason).isEqualTo("validate.bogus.missingsig_named:.:A");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void validateValid(boolean asSet) {
    JustifiedSecStatus status;
    if (asSet) {
      status = verifier.verify(new SRRset(signed), keyEntry, Instant.ofEpochSecond(5400));
    } else {
      status = verifier.verify(signed, key, Instant.ofEpochSecond(5400));
    }

    assertThat(status.status).isEqualTo(SecurityStatus.SECURE);
    assertThat(status.edeReason).isEqualTo(-1);
    assertThat(status.reason).isNull();
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void validateNotYetValid(boolean asSet) {
    JustifiedSecStatus status;
    if (asSet) {
      status = verifier.verify(new SRRset(signed), keyEntry, Instant.ofEpochSecond(1800));
    } else {
      status = verifier.verify(signed, key, Instant.ofEpochSecond(1800));
    }

    assertThat(status.status).isEqualTo(SecurityStatus.BOGUS);
    assertThat(status.edeReason).isEqualTo(ExtendedErrorCodeOption.SIGNATURE_NOT_YET_VALID);
    assertThat(status.reason).isEqualTo("dnskey.not_yet_valid");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void validateExpired(boolean asSet) {
    JustifiedSecStatus status;
    if (asSet) {
      status = verifier.verify(new SRRset(signed), keyEntry, Instant.ofEpochSecond(8000));
    } else {
      status = verifier.verify(signed, key, Instant.ofEpochSecond(8000));
    }

    assertThat(status.status).isEqualTo(SecurityStatus.BOGUS);
    assertThat(status.edeReason).isEqualTo(ExtendedErrorCodeOption.SIGNATURE_EXPIRED);
    assertThat(status.reason).isEqualTo("dnskey.expired");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void validateTooManySignatures(boolean asSet) {
    // Limit to max. 4 RRsigs
    Properties config = new Properties();
    config.put(DnsSecVerifier.MAX_VALIDATE_RRSIGS_PROPERTY, Integer.toString(NUM_RRSIGS - 1));
    verifier.init(config);

    JustifiedSecStatus status;
    if (asSet) {
      status = verifier.verify(new SRRset(multiSigned), keyEntry, Instant.ofEpochSecond(7208));
    } else {
      status = verifier.verify(multiSigned, key, Instant.ofEpochSecond(7208));
    }
    assertThat(status.status).isEqualTo(SecurityStatus.BOGUS);
    assertThat(status.edeReason).isEqualTo(ExtendedErrorCodeOption.DNSSEC_BOGUS);
    assertThat(status.reason).isEqualTo("validate.bogus.rrsigtoomany:.:A");
  }
}

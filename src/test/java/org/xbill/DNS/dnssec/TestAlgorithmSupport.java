// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.Security;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DNSSEC.Digest;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;

class TestAlgorithmSupport extends TestBase {
  @ParameterizedTest(name = "testAlgIsUnknown_{arguments}")
  @ValueSource(strings = {"rsamd5", "eccgost"})
  void testAlgIsUnknown(String param) throws IOException {
    Message response = resolver.send(createMessage(param + ".ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals("insecure.ds.noalgorithms:" + param + ".ingotronic.ch.", getReason(response));
    assertEde(ExtendedErrorCodeOption.UNSUPPORTED_DNSKEY_ALGORITHM, response);
  }

  @ParameterizedTest(name = "testEd_{arguments}")
  @ValueSource(strings = {"ed448", "ed25519"})
  void testEd(String param) throws IOException {
    try {
      Security.addProvider(new BouncyCastleProvider());
      resolver.init(new Properties());
      Message response = resolver.send(createMessage(param + ".nl./A"));
      assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
      assertRCode(Rcode.NOERROR, response.getRcode());
      assertNull(getReason(response));
      assertEde(-1, response);
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
  }

  @Test
  void testDigestIdIsUnknown() throws IOException {
    Message response = resolver.send(createMessage("unknown-alg.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertEquals("failed.ds.no_usable_digest:unknown-alg.ingotronic.ch.", getReason(response));
    assertEde(ExtendedErrorCodeOption.UNSUPPORTED_DS_DIGEST_TYPE, response);
  }

  @AlwaysOffline
  @Test
  void testUnsupportedDigestInDigestPreference() {
    Properties config = new Properties();
    config.put("dnsjava.dnssec.digest_preference", "1,2,0");
    assertThrows(IllegalArgumentException.class, () -> resolver.init(config));
  }

  @AlwaysOffline
  @Test
  void testFavoriteDigestNotInRRset() {
    Properties config = new Properties();
    config.put("dnsjava.dnssec.digest_preference", Digest.SHA384);
    ValUtils v = new ValUtils();
    v.init(config);
    SRRset set = new SRRset();
    set.addRR(
        new DSRecord(
            Name.root,
            DClass.IN,
            120,
            1234,
            Algorithm.DSA,
            Digest.SHA1,
            new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}));
    set.addRR(
        new DSRecord(
            Name.root,
            DClass.IN,
            120,
            1234,
            Algorithm.DSA,
            Digest.SHA256,
            new byte[] {
              1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
              6, 7, 8
            }));
    int digestId = v.favoriteDSDigestID(set);
    assertEquals(0, digestId);
  }

  @AlwaysOffline
  @Test
  void testOnlyUnsupportedDigestInRRset() {
    ValUtils v = new ValUtils();
    SRRset set = new SRRset();
    set.addRR(
        new DSRecord(
            Name.root,
            DClass.IN,
            120,
            1234,
            Algorithm.DSA,
            Digest.GOST3411,
            new byte[] {
              1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
              6, 7, 8
            }));
    int digestId = v.favoriteDSDigestID(set);
    assertEquals(0, digestId);
  }

  @AlwaysOffline
  @Test
  void testOnlyUnsupportedAlgorithmInRRset() {
    ValUtils v = new ValUtils();
    SRRset set = new SRRset();
    set.addRR(
        new DSRecord(
            Name.root,
            DClass.IN,
            120,
            1234,
            0 /*Unknown alg*/,
            DNSSEC.Digest.SHA1,
            new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0}));
    int digestId = v.favoriteDSDigestID(set);
    assertEquals(0, digestId);
  }
}

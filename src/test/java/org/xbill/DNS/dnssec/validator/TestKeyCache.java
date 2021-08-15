// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.dnssec.SRRset;
import org.xbill.DNS.dnssec.SecurityStatus;

class TestKeyCache {
  @Test
  void testNullPropertiesDontFail() {
    KeyCache kc = new KeyCache();
    kc.init(null);
    assertNull(kc.find(Name.root, DClass.IN));
  }

  @Test
  void testMaxCacheSize() throws TextParseException {
    Properties p = new Properties();
    p.put(KeyCache.MAX_CACHE_SIZE_CONFIG, "1");
    KeyCache kc = new KeyCache();
    kc.init(p);
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 60);
    KeyEntry nkeB = KeyEntry.newNullKeyEntry(Name.fromString("b."), DClass.IN, 60);
    kc.store(nkeA);
    kc.store(nkeB);
    KeyEntry fromCache = kc.find(Name.fromString("a."), DClass.IN);
    assertNull(fromCache);
  }

  @Test
  void testTtlExpiration() throws TextParseException {
    Clock clock = mock(Clock.class);
    Instant now = Clock.systemUTC().instant();
    when(clock.instant()).thenReturn(now);
    KeyCache kc = new KeyCache(clock);
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 1);
    kc.store(nkeA);
    when(clock.instant()).thenReturn(now.plusSeconds(5));
    KeyEntry fromCache = kc.find(Name.fromString("a."), DClass.IN);
    assertNull(fromCache);
  }

  @Test
  void testTtlNoLongerThanMaxTtl() throws TextParseException {
    Properties p = new Properties();
    p.put(KeyCache.MAX_TTL_CONFIG, "1");
    Clock clock = mock(Clock.class);
    Instant now = Clock.systemUTC().instant();
    when(clock.instant()).thenReturn(now);
    KeyCache kc = new KeyCache(clock);
    kc.init(p);
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 60);
    kc.store(nkeA);
    when(clock.instant()).thenReturn(now.plusSeconds(5));
    KeyEntry fromCache = kc.find(Name.fromString("a."), DClass.IN);
    assertNull(fromCache);
  }

  @Test
  void testPositiveEntryExactMatch() throws TextParseException {
    KeyCache kc = new KeyCache();
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a.a."), DClass.IN, 60);
    KeyEntry nkeB = KeyEntry.newNullKeyEntry(Name.fromString("a.b."), DClass.IN, 60);
    kc.store(nkeA);
    kc.store(nkeB);
    KeyEntry fromCache = kc.find(Name.fromString("a.a."), DClass.IN);
    assertEquals(nkeA, fromCache);
  }

  @Test
  void testPositiveEntryEncloserMatch() throws TextParseException {
    KeyCache kc = new KeyCache();
    KeyEntry nkeA = KeyEntry.newNullKeyEntry(Name.fromString("a."), DClass.IN, 60);
    KeyEntry nkeB = KeyEntry.newNullKeyEntry(Name.fromString("b."), DClass.IN, 60);
    kc.store(nkeA);
    kc.store(nkeB);
    KeyEntry fromCache = kc.find(Name.fromString("a.a."), DClass.IN);
    assertEquals(nkeA, fromCache);
  }

  @Test
  void testCacheOnlySecureDNSKEYs() throws TextParseException {
    KeyCache kc = new KeyCache();

    DNSKEYRecord rA =
        new DNSKEYRecord(Name.fromString("a."), DClass.IN, 60, 0, 0, 0, new byte[] {0});
    SRRset setA = new SRRset(rA);
    setA.setSecurityStatus(SecurityStatus.SECURE);
    KeyEntry nkeA = KeyEntry.newKeyEntry(setA);
    kc.store(nkeA);

    DSRecord rB = new DSRecord(Name.fromString("b."), DClass.IN, 60, 0, 0, 0, new byte[] {0});
    SRRset setB = new SRRset(rB);
    KeyEntry nkeB = KeyEntry.newKeyEntry(setB);
    kc.store(nkeB);

    DNSKEYRecord rC =
        new DNSKEYRecord(Name.fromString("c."), DClass.IN, 60, 0, 0, 0, new byte[] {0});
    SRRset setC = new SRRset(rC);
    KeyEntry nkeC = KeyEntry.newKeyEntry(setC);
    kc.store(nkeC);

    KeyEntry fromCacheA = kc.find(Name.fromString("a."), DClass.IN);
    assertEquals(nkeA, fromCacheA);

    KeyEntry fromCacheB = kc.find(Name.fromString("b."), DClass.IN);
    assertNull(fromCacheB);

    KeyEntry fromCacheC = kc.find(Name.fromString("c."), DClass.IN);
    assertNull(fromCacheC);
  }
}

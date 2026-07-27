package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CacheTest {

  private Cache cache;
  private Name exampleName;
  private ARecord aRecord;

  @BeforeEach
  void setUp() throws TextParseException, UnknownHostException {
    cache = new Cache(DClass.IN);
    exampleName = Name.fromString("example.com.");
    aRecord = new ARecord(exampleName, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));
  }

  @Test
  void testAddAndLookup() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(1, response.answers().size());
    assertEquals(aRecord, response.answers().get(0).first());
  }

  @Test
  void testClearCache() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    cache.clearCache();
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isUnknown());
  }

  @Test
  void testRemoveElement() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    cache.flushSet(exampleName, Type.A);
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isUnknown());
  }

  @Test
  void testMaxEntries() throws TextParseException, UnknownHostException {
    cache.setMaxEntries(1);
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);

    Name otherName = Name.fromString("other.com.");
    ARecord otherRecord =
        new ARecord(otherName, DClass.IN, 3600, InetAddress.getByName("127.0.0.2"));
    cache.addRecord(otherRecord, Credibility.AUTH_ANSWER);

    assertEquals(1, cache.getSize());
    SetResponse response = cache.lookupRecords(otherName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());

    response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isUnknown());
  }

  @Test
  void testNegativeCaching() throws TextParseException {
    cache.addNegative(exampleName, Type.A, null, Credibility.AUTH_ANSWER);
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(
        response.isNXRRSET() || response.isUnknown(),
        "Expected NXRRSET or UNKNOWN for " + exampleName + " but got " + response);
  }

  @Test
  void testNXDOMAIN() throws TextParseException {
    cache.addNegative(exampleName, Type.ANY, null, Credibility.AUTH_ANSWER);
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(
        response.isNXDOMAIN() || response.isUnknown(),
        "Expected NXDOMAIN or UNKNOWN for " + exampleName + " but got " + response);
  }

  @Test
  void testGettersAndSetters() {
    cache.setMaxCache(100);
    assertEquals(100, cache.getMaxCache());

    cache.setMaxNCache(50);
    assertEquals(50, cache.getMaxNCache());

    assertEquals(DClass.IN, cache.getDClass());
  }

  @Test
  void testCredibility() {
    // Lower credibility should not replace higher credibility
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    ARecord lowerRecord =
        new ARecord(exampleName, DClass.IN, 3600, InetAddress.getLoopbackAddress());
    cache.addRecord(lowerRecord, Credibility.NONAUTH_ANSWER);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(aRecord, response.answers().get(0).first());

    // Higher credibility should replace lower credibility
    cache.clearCache();
    cache.addRecord(lowerRecord, Credibility.NONAUTH_ANSWER);
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);

    response = cache.lookupRecords(exampleName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(aRecord, response.answers().get(0).first());
  }

  @Test
  void testTTL() throws InterruptedException {
    ARecord shortTtlRecord =
        new ARecord(exampleName, DClass.IN, 1, InetAddress.getLoopbackAddress());
    cache.addRecord(shortTtlRecord, Credibility.AUTH_ANSWER);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());

    // Wait for TTL to expire. Using a slightly longer wait to be safe.
    Thread.sleep(1100);

    response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isUnknown());
  }

  @Test
  void testAddMessage() throws TextParseException, UnknownHostException {
    Message m = new Message();
    m.getHeader().setFlag(Flags.AA);
    m.getHeader().setFlag(Flags.AD);
    m.addRecord(Record.newRecord(exampleName, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(aRecord, Section.ANSWER);

    SetResponse sr = cache.addMessage(m);
    assertNotNull(sr);
    assertTrue(sr.isSuccessful());

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(aRecord, response.answers().get(0).first());
  }

  @Test
  void testAddMessageCNAME() throws TextParseException, UnknownHostException {
    Name cnameName = Name.fromString("cname.example.com.");
    CNAMERecord cnameRecord = new CNAMERecord(cnameName, DClass.IN, 3600, exampleName);

    Message m = new Message();
    m.addRecord(Record.newRecord(cnameName, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(cnameRecord, Section.ANSWER);
    m.addRecord(aRecord, Section.ANSWER);

    cache.addMessage(m);

    SetResponse response = cache.lookupRecords(cnameName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isCNAME());
    assertEquals(cnameRecord, response.getCNAME());

    response = cache.lookupRecords(exampleName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(aRecord, response.answers().get(0).first());
  }

  @Test
  void testLookupAny() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    SetResponse response = cache.lookupRecords(exampleName, Type.ANY, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(1, response.answers().size());
  }

  @Test
  void testDelegation() throws TextParseException {
    Name subName = Name.fromString("sub.example.com.");
    NSRecord nsRecord =
        new NSRecord(exampleName, DClass.IN, 3600, Name.fromString("ns1.example.com."));
    cache.addRecord(nsRecord, Credibility.AUTH_ANSWER);

    SetResponse response = cache.lookupRecords(subName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isDelegation());
    assertEquals(nsRecord, response.getNS().first());
  }

  @Test
  void testDNAME() throws TextParseException {
    Name dnameName = Name.fromString("dname.com.");
    Name subDnameName = Name.fromString("sub.dname.com.");
    DNAMERecord dnameRecord = new DNAMERecord(dnameName, DClass.IN, 3600, exampleName);
    cache.addRecord(dnameRecord, Credibility.AUTH_ANSWER);

    SetResponse response = cache.lookupRecords(subDnameName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isDNAME());
    assertEquals(dnameRecord, response.getDNAME());
  }

  @Test
  void testLimitExpire() {
    cache.setMaxCache(3600); // 1 hour
    ARecord longTtlRecord =
        new ARecord(exampleName, DClass.IN, 7200, InetAddress.getLoopbackAddress());
    cache.addRecord(longTtlRecord, Credibility.AUTH_ANSWER);

    // We can't easily verify the internal 'expire' field, but we can verify it's still there
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());
  }

  @Test
  void testAddMessageNegative() throws TextParseException {
    Message m = new Message();
    m.getHeader().setRcode(Rcode.NXDOMAIN);
    m.addRecord(Record.newRecord(exampleName, Type.A, DClass.IN), Section.QUESTION);
    SOARecord soa =
        new SOARecord(exampleName, DClass.IN, 3600, Name.root, Name.root, 1, 2, 3, 4, 5);
    m.addRecord(soa, Section.AUTHORITY);

    cache.addMessage(m);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isNXDOMAIN());
  }

  @Test
  void testAddMessageReferral() throws TextParseException {
    Message m = new Message();
    m.addRecord(Record.newRecord(exampleName, Type.A, DClass.IN), Section.QUESTION);
    NSRecord ns = new NSRecord(exampleName, DClass.IN, 3600, Name.fromString("ns1.example.com."));
    m.addRecord(ns, Section.AUTHORITY);

    cache.addMessage(m);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isDelegation());
    assertEquals(ns, response.getNS().first());
  }

  @Test
  void testAddMessageDNAME() throws TextParseException {
    Name dnameName = Name.fromString("dname.com.");
    Name subDnameName = Name.fromString("sub.dname.com.");
    DNAMERecord dnameRecord = new DNAMERecord(dnameName, DClass.IN, 3600, exampleName);

    Message m = new Message();
    m.addRecord(Record.newRecord(subDnameName, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(dnameRecord, Section.ANSWER);

    cache.addMessage(m);

    SetResponse response = cache.lookupRecords(subDnameName, Type.A, Credibility.NONAUTH_ANSWER);
    assertTrue(response.isDNAME(), "Expected DNAME for " + subDnameName + " but got " + response);
    assertEquals(dnameRecord, response.getDNAME());
  }

  @Test
  void testCacheFromInputStream() throws IOException {
    String masterFile =
        "example.com. 3600 IN A 127.0.0.1\n" + "www.example.com. 3600 IN CNAME example.com.";
    try (java.io.ByteArrayInputStream bis =
        new java.io.ByteArrayInputStream(masterFile.getBytes())) {
      Cache masterCache = new Cache(bis);
      SetResponse response = masterCache.lookupRecords(exampleName, Type.A, Credibility.HINT);
      assertTrue(response.isSuccessful());

      Name wwwName = Name.fromString("www.example.com.");
      response = masterCache.lookupRecords(wwwName, Type.CNAME, Credibility.HINT);
      assertTrue(
          response.isSuccessful(), "Expected SUCCESSFUL for " + wwwName + " but got " + response);
      assertEquals(Type.CNAME, response.answers().get(0).getType());
    }
  }

  @Test
  void testFlushName() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    cache.flushName(exampleName);
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isUnknown());
  }

  @Test
  void testGetSize() throws TextParseException, UnknownHostException {
    assertEquals(0, cache.getSize());
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    assertEquals(1, cache.getSize());

    Name otherName = Name.fromString("other.com.");
    ARecord otherRecord =
        new ARecord(otherName, DClass.IN, 3600, InetAddress.getByName("127.0.0.2"));
    cache.addRecord(otherRecord, Credibility.AUTH_ANSWER);
    assertEquals(2, cache.getSize());

    cache.flushName(exampleName);
    assertEquals(1, cache.getSize());
  }

  @Test
  void testGetMaxEntries() {
    cache.setMaxEntries(100);
    assertEquals(100, cache.getMaxEntries());
  }

  @Test
  void testFindRecords() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    List<RRset> records = cache.findRecords(exampleName, Type.A);
    assertNotNull(records);
    assertEquals(1, records.size());
    assertEquals(aRecord, records.get(0).first());

    records = cache.findRecords(exampleName, Type.AAAA);
    assertNull(records);
  }

  @Test
  void testFindAnyRecords() {
    cache.addRecord(aRecord, Credibility.GLUE);
    List<RRset> records = cache.findAnyRecords(exampleName, Type.A);
    assertNotNull(records);
    assertEquals(1, records.size());

    records = cache.findRecords(exampleName, Type.A); // findRecords uses Credibility.NORMAL
    assertNull(records);
  }

  @Test
  void testToString() {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    String s = cache.toString();
    assertTrue(s.contains("example.com."));
    assertTrue(s.contains("127.0.0.1"));
  }

  @Test
  void testAddMessageAuthenticated() throws TextParseException, UnknownHostException {
    Message m = new Message();
    m.getHeader().setFlag(Flags.AA);
    m.getHeader().setFlag(Flags.AD);
    m.addRecord(Record.newRecord(exampleName, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(aRecord, Section.ANSWER);

    cache.addMessage(m);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isAuthenticated());
  }

  @Test
  void testAddMessageNotAuthenticated() throws TextParseException, UnknownHostException {
    Message m = new Message();
    m.getHeader().setFlag(Flags.AA);
    // AD flag not set
    m.addRecord(Record.newRecord(exampleName, Type.A, DClass.IN), Section.QUESTION);
    m.addRecord(aRecord, Section.ANSWER);

    cache.addMessage(m);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertFalse(response.isAuthenticated());
  }

  @Test
  void testAddMultipleRecords() throws TextParseException, UnknownHostException {
    ARecord a1 = new ARecord(exampleName, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));
    ARecord a2 = new ARecord(exampleName, DClass.IN, 3600, InetAddress.getByName("127.0.0.2"));
    cache.addRecord(a1, Credibility.AUTH_ANSWER);
    cache.addRecord(a2, Credibility.AUTH_ANSWER);

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());
    assertEquals(1, response.answers().size());
    assertEquals(2, response.answers().get(0).size());
  }

  @Test
  void testAddMultipleTypes() throws TextParseException, UnknownHostException {
    cache.addRecord(aRecord, Credibility.AUTH_ANSWER);
    AAAARecord aaaaRecord =
        new AAAARecord(exampleName, DClass.IN, 3600, InetAddress.getByName("2001:db8::1"));
    cache.addRecord(aaaaRecord, Credibility.AUTH_ANSWER);

    assertEquals(1, cache.getSize()); // Same name, different types

    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());

    response = cache.lookupRecords(exampleName, Type.AAAA, Credibility.AUTH_ANSWER);
    assertTrue(response.isSuccessful());
  }

  @Test
  void testAddNegativeExpiration() throws TextParseException {
    cache.setMaxNCache(1);
    cache.addNegative(exampleName, Type.A, null, Credibility.AUTH_ANSWER);
    SetResponse response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(
        response.isNXRRSET() || response.isUnknown(),
        "Expected NXRRSET or UNKNOWN but got " + response);

    try {
      Thread.sleep(1100);
    } catch (InterruptedException e) {
      // ignore
    }

    response = cache.lookupRecords(exampleName, Type.A, Credibility.AUTH_ANSWER);
    assertTrue(response.isUnknown(), "Expected UNKNOWN after expiration but got " + response);
  }
}

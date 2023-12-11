// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ZoneTest {
  private static final ARecord A_TEST;
  private static final AAAARecord AAAA_1_TEST;
  private static final AAAARecord AAAA_2_TEST;
  private static final ARecord A_WILD;
  private static final TXTRecord TXT_WILD;
  private static final Zone ZONE;

  static {
    try {
      Name nameZone = new Name("example.");
      InetAddress localhost4 = InetAddress.getByName("127.0.0.1");
      InetAddress localhost6a = InetAddress.getByName("::1");
      InetAddress localhost6b = InetAddress.getByName("::2");
      A_TEST = new ARecord(new Name("test", nameZone), DClass.IN, 3600, localhost4);
      AAAA_1_TEST = new AAAARecord(new Name("test", nameZone), DClass.IN, 3600, localhost6a);
      AAAA_2_TEST = new AAAARecord(new Name("test", nameZone), DClass.IN, 3600, localhost6b);
      A_WILD = new ARecord(new Name("*", nameZone), DClass.IN, 3600, localhost4);
      TXT_WILD = new TXTRecord(new Name("*", nameZone), DClass.IN, 3600, "sometext");

      Record[] zoneRecords =
          new Record[] {
            new SOARecord(
                nameZone,
                DClass.IN,
                3600L,
                Name.fromConstantString("nameserver."),
                new Name("hostmaster", nameZone),
                1,
                21600L,
                7200L,
                2160000L,
                3600L),
            new NSRecord(nameZone, DClass.IN, 300L, Name.fromConstantString("nameserver.")),
            A_TEST,
            AAAA_1_TEST,
            AAAA_2_TEST,
            A_WILD,
            TXT_WILD,
          };
      ZONE = new Zone(nameZone, zoneRecords);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  void exactNameExistingALookup() {
    Name testName = Name.fromConstantString("test.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.A);
    assertEquals(oneRRset(A_TEST), resp.answers());
  }

  @Test
  void exactNameTwoAaaaLookup() {
    Name testName = Name.fromConstantString("test.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.AAAA);
    assertEquals(oneRRset(AAAA_1_TEST, AAAA_2_TEST), resp.answers());
  }

  @Test
  void exactNameAnyLookup() {
    Name testName = Name.fromConstantString("test.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.ANY);
    assertTrue(resp.isSuccessful());
    assertEquals(listOf(new RRset(A_TEST), new RRset(AAAA_1_TEST, AAAA_2_TEST)), resp.answers());
  }

  @Test
  void wildNameExistingALookup() {
    Name testName = Name.fromConstantString("undefined.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.A);
    assertEquals(oneRRset(A_WILD.withName(testName)), resp.answers());
  }

  @Test
  void wildNameExistingTxtLookup() {
    Name testName = Name.fromConstantString("undefined.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.TXT);
    assertEquals(oneRRset(TXT_WILD.withName(testName)), resp.answers());
  }

  @Test
  void wildNameNonExistingMxLookup() {
    SetResponse resp = ZONE.findRecords(Name.fromConstantString("undefined.example."), Type.MX);
    assertTrue(resp.isNXDOMAIN());
  }

  @Test
  void wildNameAnyLookup() {
    Name testName = Name.fromConstantString("undefined.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.ANY);
    assertTrue(resp.isSuccessful());
    assertEquals(
        listOf(new RRset(A_WILD.withName(testName)), new RRset(TXT_WILD.withName(testName))),
        resp.answers());
  }

  @Test
  void testReadLocksAreAcquiredAndReleasedCorrectNumberOfTimes() {
    Name testName = Name.fromConstantString("test.example.");
    ReentrantReadWriteLock.ReadLock readLock = mock(ReentrantReadWriteLock.ReadLock.class);
    ZONE.setLock(readLock);
    SetResponse resp = ZONE.findRecords(testName, Type.ANY);
    verify(readLock, times(5)).lock();
    verify(readLock, times(5)).unlock();
  }

  private static List<RRset> listOf(RRset... rrsets) {
    return Stream.of(rrsets).collect(Collectors.toList());
  }

  private static List<RRset> oneRRset(Record... r) {
    return Collections.singletonList(new RRset(r));
  }
}

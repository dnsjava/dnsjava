// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ZoneTest {
  private Name ZONE_NAME;
  private SOARecord SOA1;
  private SOARecord SOA2;
  private NSRecord NS1;
  private NSRecord NS2;
  private ARecord A_UNIQUE;
  private ARecord A_1_TEST;
  private ARecord A_2_TEST;
  private AAAARecord AAAA_1_TEST;
  private AAAARecord AAAA_2_TEST;
  private ARecord A_WILD;
  private TXTRecord TXT_WILD;
  private Zone ZONE;

  @BeforeEach
  void beforeEach() throws IOException {
    ZONE_NAME = Name.fromConstantString("example.");
    SOA1 =
        new SOARecord(
            ZONE_NAME,
            DClass.IN,
            3600L,
            Name.fromConstantString("nameserver."),
            new Name("hostadmin", ZONE_NAME),
            1,
            21600L,
            7200L,
            2160000L,
            3600L);
    SOA2 =
        new SOARecord(
            ZONE_NAME,
            DClass.IN,
            3600L,
            Name.fromConstantString("nameserver."),
            new Name("zoneadmin", ZONE_NAME),
            1,
            21600L,
            7200L,
            2160000L,
            3600L);
    NS1 = new NSRecord(ZONE_NAME, DClass.IN, 300L, Name.fromConstantString("nameserver1."));
    NS2 = new NSRecord(ZONE_NAME, DClass.IN, 300L, Name.fromConstantString("nameserver2."));

    InetAddress localhost4 = InetAddress.getByName("127.0.0.1");
    InetAddress localhost6a = InetAddress.getByName("::1");
    InetAddress localhost6b = InetAddress.getByName("::2");
    A_UNIQUE =
        new ARecord(
            new Name("unique", ZONE_NAME), DClass.IN, 3600, InetAddress.getByName("127.0.0.3"));
    A_1_TEST = new ARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, localhost4);
    A_2_TEST = new ARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, new byte[] {127, 0, 0, 2});
    AAAA_1_TEST = new AAAARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, localhost6a);
    AAAA_2_TEST = new AAAARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, localhost6b);
    A_WILD =
        new ARecord(
            new Name("*.wild", ZONE_NAME), DClass.IN, 3600, InetAddress.getByName("127.0.0.2"));
    TXT_WILD = new TXTRecord(new Name("*.wild", ZONE_NAME), DClass.IN, 3600, "sometext");

    Record[] zoneRecords =
        new Record[] {
          SOA1, NS1, NS2, A_UNIQUE, A_1_TEST, AAAA_1_TEST, AAAA_2_TEST, A_WILD, TXT_WILD,
        };
    ZONE = new Zone(ZONE_NAME, zoneRecords);
  }

  @Test
  void exactNameNull() {
    assertThatThrownBy(() -> ZONE.findExactMatch(null, Type.A))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
    assertThatThrownBy(() -> ZONE.findExactMatch(null, -1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
    assertThatThrownBy(() -> ZONE.findExactMatch(Name.root, -1))
        .isInstanceOf(InvalidTypeException.class)
        .hasMessageContaining("type");
  }

  @Test
  void exactNameExistingALookup() {
    assertThat(ZONE.findExactMatch(A_1_TEST.getName(), Type.A))
        .isNotNull()
        .containsExactly(A_1_TEST);
  }

  @Test
  void exactNameAnyThrow() {
    Name name = A_1_TEST.getName();
    assertThatThrownBy(() -> ZONE.findExactMatch(name, Type.ANY))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("type ANY");
  }

  @Test
  void findNameExistingALookup() {
    SetResponse resp = ZONE.findRecords(A_1_TEST.getName(), Type.A);
    assertEquals(oneRRset(A_1_TEST), resp.answers());
  }

  @Test
  void findNameNXRRsetLookup() {
    SetResponse resp = ZONE.findRecords(A_1_TEST.getName(), Type.TXT);
    assertEquals(SetResponse.ofType(SetResponseType.NXRRSET), resp);
  }

  @Test
  void findNameTwoAaaaLookup() {
    SetResponse resp = ZONE.findRecords(AAAA_1_TEST.getName(), Type.AAAA);
    assertEquals(oneRRset(AAAA_1_TEST, AAAA_2_TEST), resp.answers());
  }

  @Test
  void findNameAnyLookup() {
    SetResponse resp = ZONE.findRecords(A_1_TEST.getName(), Type.ANY);
    assertTrue(resp.isSuccessful());
    assertEquals(listOf(new RRset(A_1_TEST), new RRset(AAAA_1_TEST, AAAA_2_TEST)), resp.answers());
  }

  @Test
  void findWildNameNull() {
    assertThatThrownBy(() -> ZONE.findRecords(null, Type.A))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
    assertThatThrownBy(() -> ZONE.findRecords(null, -1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
    assertThatThrownBy(() -> ZONE.findRecords(Name.root, -1))
        .isInstanceOf(InvalidTypeException.class)
        .hasMessageContaining("type");
  }

  @Test
  void findWildNameNotSubdomain() {
    assertThat(ZONE.findRecords(Name.root, Type.A))
        .isNotNull()
        .isEqualTo(SetResponse.ofType(SetResponseType.NXDOMAIN));
  }

  @Test
  void findWildNameExistingALookup() {
    Name testName = Name.fromConstantString("undefined.wild.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.A);
    assertThat(resp.answers()).containsExactly(new RRset(A_WILD.withName(testName)));
  }

  @Test
  void findWildNameExistingTxtLookup() {
    Name testName = Name.fromConstantString("undefined.wild.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.TXT);
    assertThat(resp.answers())
        .as(ZONE + "\nmust contain rrset for\n" + TXT_WILD.withName(testName))
        .containsExactly(new RRset(TXT_WILD.withName(testName)));
    assertThat(resp.isSuccessful()).isTrue();
  }

  @Test
  void findWildNameNonExistingMxLookup() {
    // a wildcard match without the queried type must answer NODATA (not NXDOMAIN)
    SetResponse resp =
        ZONE.findRecords(Name.fromConstantString("undefined.wild.example."), Type.MX);
    assertThat(resp.isNXDOMAIN()).isFalse();
    assertThat(resp.isNXRRSET()).isTrue();
  }

  @Test
  void findWildNameAnyLookup() {
    Name testName = Name.fromConstantString("undefined.wild.example.");
    SetResponse resp = ZONE.findRecords(testName, Type.ANY);
    assertThat(resp.isSuccessful()).isTrue();
    assertThat(resp.answers())
        .containsExactly(
            new RRset(A_WILD.withName(testName)), new RRset(TXT_WILD.withName(testName)));
  }

  @Test
  void ctorNull() {
    InputStream is = new ByteArrayInputStream(new byte[0]);
    assertThatThrownBy(() -> new Zone(null, is))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("zone name");
    assertThatThrownBy(() -> new Zone(ZONE_NAME, (InputStream) null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("input stream");
    assertThatThrownBy(() -> new Zone(null, (String) null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(null, (Record[]) null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(Name.root, (String) null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(Name.root, (Record[]) null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(null, "some-file.dns"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(null, new Record[0]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(null)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(null, DClass.IN, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(Name.root, DClass.IN, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(null, DClass.IN, "localhost"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new Zone(Name.root, -1, "localhost"))
        .isInstanceOf(InvalidDClassException.class);
  }

  @Test
  void ctorMissingRecords() {
    assertThrows(IOException.class, () -> new Zone(Name.root, new Record[0]));
    assertThrows(IOException.class, () -> new Zone(Name.root, new Record[] {A_1_TEST}));
    assertThatThrownBy(() -> new Zone(Name.root, new Record[] {SOA1}))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("SOA owner");
    assertThatThrownBy(() -> new Zone(ZONE_NAME, new Record[] {SOA1, NS1, SOA2}))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("exactly 1 SOA");
    assertThatThrownBy(() -> new Zone(ZONE_NAME, new Record[] {SOA1}))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("no NS set");
  }

  @Test
  void ctorInputStream() {
    Zone zone =
        assertDoesNotThrow(
            () ->
                new Zone(
                    Name.fromConstantString("example.com."),
                    ZoneTest.class.getResourceAsStream("/zonefileEx2")));
    assertThat(zone.iterator().hasNext()).isTrue();
    RRset set = zone.iterator().next();
    assertThat(set.getType()).isEqualTo(Type.SOA);
    assertThat(set.rrs(false)).hasSize(1);
    assertThat(set.sigs()).hasSize(1);
  }

  @Test
  void ctorWithoutOrigin() {
    Zone zone =
        assertDoesNotThrow(
            () ->
                new Zone(
                    Name.fromConstantString("example.com."),
                    ZoneTest.class.getResourceAsStream("/zonefileEx3")));
    assertThat(zone.iterator().hasNext()).isTrue();
    RRset set = zone.iterator().next();
    assertThat(set.getType()).isEqualTo(Type.SOA);
    assertThat(set.rrs(false)).hasSize(1);
  }

  @Test
  void addRecord() throws TextParseException {
    Name n = new Name("something", ZONE_NAME);
    assertNull(ZONE.findExactMatch(n, Type.A));
    ZONE.addRecord(A_1_TEST.withName(n));
    assertNotNull(ZONE.findExactMatch(n, Type.A));
  }

  @Test
  void addRecordExistingName() {
    Name n = A_1_TEST.getName();
    assertNotNull(ZONE.findExactMatch(n, Type.A));
    assertNull(ZONE.findExactMatch(n, Type.MX));
    MXRecord mx = new MXRecord(n, DClass.IN, 3600, 1, Name.root);
    ZONE.addRecord(mx);
    assertThat(ZONE.findExactMatch(n, Type.MX)).isNotNull().containsExactly(mx);
  }

  @Test
  void addRecordExistingSet() {
    Name n = A_1_TEST.getName();
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(A_1_TEST);
    ARecord a2 = new ARecord(n, DClass.IN, 3600, new byte[4]);
    ZONE.addRecord(a2);
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(A_1_TEST, a2);
  }

  @Test
  void addRecordExistingSetOneType() {
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A))
        .isNotNull()
        .containsExactly(A_UNIQUE);
    // Add a different record, testing that it was added to the existing set
    ARecord a2 = new ARecord(A_UNIQUE.getName(), DClass.IN, 3600, new byte[4]);
    assertDoesNotThrow(() -> ZONE.addRecord(a2));
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A))
        .isNotNull()
        .containsExactly(A_UNIQUE, a2);
  }

  @Test
  void removeRecord() {
    assertNotNull(ZONE.findExactMatch(A_1_TEST.getName(), Type.A));
    ZONE.removeRecord(A_1_TEST);
    assertNull(ZONE.findExactMatch(A_1_TEST.getName(), Type.A));
  }

  @Test
  void removeRecordNotInZone() {
    assertThat(ZONE.findExactMatch(A_1_TEST.getName(), Type.A)).isNotNull();
    String zoneBefore = ZONE.toMasterFile();
    ZONE.removeRecord(A_2_TEST);
    assertThat(ZONE.findExactMatch(A_1_TEST.getName(), Type.A)).isNotNull();
    assertThat(ZONE.toMasterFile()).isEqualTo(zoneBefore);
  }

  @Test
  void addRRset() throws TextParseException {
    Name n = new Name("something", ZONE_NAME);
    assertNull(ZONE.findExactMatch(n, Type.A));
    ZONE.addRRset(new RRset(A_1_TEST.withName(n)));
    assertNotNull(ZONE.findExactMatch(n, Type.A));
  }

  @Test
  void addRRsetExistingName() {
    Name n = A_1_TEST.getName();
    assertNotNull(ZONE.findExactMatch(n, Type.A));
    assertNull(ZONE.findExactMatch(n, Type.MX));
    MXRecord mx = new MXRecord(n, DClass.IN, 3600, 1, Name.root);
    ZONE.addRRset(new RRset(mx));
    assertThat(ZONE.findExactMatch(n, Type.MX)).isNotNull().containsExactly(mx);
  }

  @Test
  void addRRsetExistingSet() {
    Name n = A_1_TEST.getName();
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(A_1_TEST);
    ARecord a2 = new ARecord(n, DClass.IN, 3600, new byte[4]);
    ZONE.addRRset(new RRset(a2));
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(a2);
  }

  @Test
  void addRRsetExistingSetOneType() {
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A))
        .isNotNull()
        .containsExactly(A_UNIQUE);

    // Add a new set with a different record, testing that it replaced the existing set
    ARecord a2 = new ARecord(A_UNIQUE.getName(), DClass.IN, 3600, new byte[4]);
    assertDoesNotThrow(() -> ZONE.addRRset(new RRset(a2)));
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A)).isNotNull().containsExactly(a2);
  }

  @Test
  void addRecordNull() {
    assertThatThrownBy(() -> ZONE.addRecord(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
  }

  @Test
  void addRRsetNull() {
    assertThatThrownBy(() -> ZONE.addRRset(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
  }

  @Test
  void addRecordOutOfZone() {
    Record arecord = A_1_TEST.withName(Name.root);
    assertThatThrownBy(() -> ZONE.addRecord(arecord))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("subdomain");
  }

  @Test
  void addRRsetOutOfZone() {
    RRset aset = new RRset(A_1_TEST.withName(Name.root));
    assertThatThrownBy(() -> ZONE.addRRset(aset))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("subdomain");
  }

  @Test
  void addSOARecordNewName() {
    SOARecord newSoa = (SOARecord) SOA2.withName(Name.root);
    assertThatThrownBy(() -> ZONE.addRecord(newSoa))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("SOA owner");
  }

  @Test
  void addSOARRsetNewName() {
    SOARecord newSoa = (SOARecord) SOA2.withName(Name.root);
    RRset soaSet = new RRset(newSoa);
    assertThatThrownBy(() -> ZONE.addRRset(soaSet))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("SOA owner");
  }

  @Test
  void addSOARecordReplaceExisting() {
    ZONE.addRecord(SOA2);
    RRset soa = ZONE.findExactMatch(ZONE_NAME, Type.SOA);
    assertThat(ZONE.getSOA()).isEqualTo(SOA2);
    assertThat(soa).isNotNull().containsExactly(SOA2);
  }

  @Test
  void addSOARRsetReplaceExisting() {
    ZONE.addRRset(new RRset(SOA2));
    RRset soa = ZONE.findExactMatch(ZONE_NAME, Type.SOA);
    assertThat(soa).isNotNull();
    assertThat(soa.size()).isEqualTo(1);
    assertThat(soa.first()).isEqualTo(ZONE.getSOA()).isEqualTo(SOA2);
  }

  @Test
  void addSOARRsetCheckSize() {
    RRset soaSet = new RRset(SOA1, SOA2);
    assertThatThrownBy(() -> ZONE.addRRset(soaSet))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exactly 1 SOA");
    assertThat(ZONE.getSOA()).isNotNull().isEqualTo(SOA1);
  }

  @Test
  void removeSOARecord() {
    SOARecord soa = ZONE.getSOA();
    assertThatThrownBy(() -> ZONE.removeRecord(soa))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("remove SOA");
    RRset soaSet = ZONE.findExactMatch(ZONE_NAME, Type.SOA);
    assertThat(soaSet).isNotNull().containsExactly(ZONE.getSOA());
  }

  @Test
  void removeRecordNull() {
    assertThatThrownBy(() -> ZONE.removeRecord(null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
  }

  @Test
  void removeRecordNonExisting() throws TextParseException {
    Name n = new Name("some", ZONE_NAME);
    RRset some = ZONE.findExactMatch(n, Type.DS);
    assertThat(some).isNull();
    assertDoesNotThrow(() -> ZONE.removeRecord(Record.newRecord(n, Type.DS, DClass.IN, 3600)));
  }

  @Test
  void removeRecordUniqueType() {
    RRset some = ZONE.findExactMatch(A_UNIQUE.getName(), Type.A);
    assertThat(some).isNotNull();
    assertDoesNotThrow(() -> ZONE.removeRecord(A_UNIQUE));
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A)).isNull();
  }

  @Test
  void removeRecordNs() {
    RRset nsSet = ZONE.findExactMatch(ZONE_NAME, Type.NS);
    assertThat(nsSet).containsExactly(NS1, NS2);
    ZONE.removeRecord(NS1);
    nsSet = ZONE.findExactMatch(ZONE_NAME, Type.NS);
    assertThat(nsSet).containsExactly(NS2);
    assertThatThrownBy(() -> ZONE.removeRecord(NS2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("all NS");
    nsSet = ZONE.findExactMatch(ZONE_NAME, Type.NS);
    assertThat(nsSet).containsExactly(NS2);
  }

  @Test
  void removeRRsetNull() {
    assertThatThrownBy(() -> ZONE.removeRRset(null, Type.A))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
    assertThatThrownBy(() -> ZONE.removeRRset(null, -1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("null");
    assertThatThrownBy(() -> ZONE.removeRRset(Name.root, -1))
        .isInstanceOf(InvalidTypeException.class);
  }

  @Test
  void removeRRsetNotExisting() throws TextParseException {
    Name n = new Name("some", ZONE_NAME);
    RRset some = ZONE.findExactMatch(n, Type.DS);
    assertThat(some).isNull();
    assertDoesNotThrow(() -> ZONE.removeRRset(n, Type.DS));
  }

  @Test
  void removeRRsetMultiple() throws TextParseException {
    Name n = new Name("*.wild", ZONE_NAME);
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull();
    assertThat(ZONE.findExactMatch(n, Type.TXT)).isNotNull();
    assertDoesNotThrow(() -> ZONE.removeRRset(n, Type.TXT));
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull();
    assertThat(ZONE.findExactMatch(n, Type.TXT)).isNull();
  }

  @Test
  void removeSOARRset() {
    assertThatThrownBy(() -> ZONE.removeRRset(ZONE_NAME, Type.SOA))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("remove SOA");
    assertThat(ZONE.findExactMatch(ZONE_NAME, Type.SOA)).isNotNull().containsExactly(SOA1);
    assertThat(ZONE.getSOA()).isNotNull();
  }

  @Test
  void removeNSRRset() {
    assertThatThrownBy(() -> ZONE.removeRRset(ZONE_NAME, Type.NS))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("remove all NS");
    assertThat(ZONE.findExactMatch(ZONE_NAME, Type.NS)).isNotNull();
    assertThat(ZONE.getNS()).isNotNull().containsExactly(NS1, NS2);
  }

  @Test
  void removeRRsetUniqueType() {
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A)).isNotNull();
    assertDoesNotThrow(() -> ZONE.removeRRset(A_UNIQUE.getName(), Type.A));
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A)).isNull();
  }

  @Test
  void removeRRsetUniqueTypeNonExisting() {
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A)).isNotNull();
    assertDoesNotThrow(() -> ZONE.removeRRset(A_UNIQUE.getName(), Type.MX));
    assertThat(ZONE.findExactMatch(A_UNIQUE.getName(), Type.A)).isNotNull();
  }

  @Test
  void getNsReturnsSetCopyOfNs() {
    RRset nsSet = ZONE.getNS();
    assertThat(nsSet).containsExactly(NS1, NS2);
    nsSet.deleteRR(nsSet.first());
    assertThat(nsSet).hasSize(1).containsExactly(NS2);
    assertThat(ZONE.getNS().rrs(false)).hasSize(2).containsExactly(NS1, NS2);
  }

  @Test
  void removeAllTypes() {
    Name n = A_1_TEST.getName();
    assertThat(n).isEqualTo(AAAA_1_TEST.getName());
    assertDoesNotThrow(() -> ZONE.removeRRset(n, Type.A));
    assertThat(ZONE.findExactMatch(n, Type.A)).isNull();
    assertDoesNotThrow(() -> ZONE.removeRRset(n, Type.AAAA));
    assertThat(ZONE.findExactMatch(n, Type.AAAA)).isNull();
    SetResponse any = assertDoesNotThrow(() -> ZONE.findRecords(n, Type.ANY));
    assertThat(any).isNotNull();
    assertThat(any.isNXDOMAIN()).isTrue();
  }

  @Test
  void iteratorHasAllInOrder() {
    assertThat(ZONE)
        .hasSize(7)
        .containsExactly(
            new RRset(SOA1),
            new RRset(NS1, NS2),
            new RRset(A_1_TEST),
            new RRset(AAAA_1_TEST, AAAA_2_TEST),
            new RRset(A_UNIQUE),
            new RRset(A_WILD),
            new RRset(TXT_WILD));
  }

  @Test
  void iteratorHasAllInOrderWithNamesAtOrigin() {
    MXRecord mx = new MXRecord(ZONE_NAME, DClass.IN, 3600, 1, A_1_TEST.getName());
    ZONE.addRecord(mx);
    assertThat(ZONE)
        .hasSize(8)
        .containsExactly(
            new RRset(SOA1),
            new RRset(NS1, NS2),
            new RRset(mx),
            new RRset(A_1_TEST),
            new RRset(AAAA_1_TEST, AAAA_2_TEST),
            new RRset(A_UNIQUE),
            new RRset(A_WILD),
            new RRset(TXT_WILD));
  }

  @Test
  void iteratorHasAllInOrderWithNamesAtOriginForAXFR() {
    MXRecord mx = new MXRecord(ZONE_NAME, DClass.IN, 3600, 1, A_1_TEST.getName());
    ZONE.addRecord(mx);
    assertThat(ZONE.AXFR())
        .toIterable()
        .hasSize(9)
        .containsExactly(
            new RRset(SOA1),
            new RRset(NS1, NS2),
            new RRset(mx),
            new RRset(A_1_TEST),
            new RRset(AAAA_1_TEST, AAAA_2_TEST),
            new RRset(A_UNIQUE),
            new RRset(A_WILD),
            new RRset(TXT_WILD),
            new RRset(SOA1));
  }

  @Test
  void iteratorHasAllInOrderOrignOnly() throws IOException {
    assertThat(new Zone(ZONE_NAME, SOA1, NS1, NS2))
        .hasSize(2)
        .containsExactly(new RRset(SOA1), new RRset(NS1, NS2));
  }

  @Test
  void iteratorReturnsSetCopyOfSoa() {
    RRset soaSet = ZONE.iterator().next();
    assertThat(soaSet).containsExactly(SOA1);
    soaSet.deleteRR(soaSet.first());
    assertThat(ZONE.getSOA()).isNotNull();
  }

  @Test
  void iteratorReturnsSetCopyOfNs() {
    Iterator<RRset> it = ZONE.iterator();
    it.next(); // Skip SOA
    RRset nsSet = it.next();
    assertThat(nsSet).containsExactly(NS1, NS2);
    nsSet.deleteRR(nsSet.first());
    assertThat(nsSet).hasSize(1).containsExactly(NS2);
    assertThat(ZONE.getNS().rrs(false)).hasSize(2).containsExactly(NS1, NS2);
  }

  @Test
  void iteratorReturnsSetCopy() {
    Iterator<RRset> it = ZONE.iterator();
    it.next(); // Skip SOA
    it.next(); // Skip NS
    RRset aSet = it.next();
    assertThat(aSet).containsExactly(A_1_TEST);
    aSet.deleteRR(aSet.first());
    assertThat(aSet).isEmpty();
    assertThat(ZONE.findExactMatch(A_1_TEST.getName(), Type.A)).hasSize(1);
  }

  @Test
  void iteratorRemoveSOAFails() {
    Iterator<RRset> iterator = ZONE.iterator();
    assertThat(iterator).isNotNull();
    assertThat(iterator.hasNext()).isTrue();
    assertThat(iterator.next()).isEqualTo(new RRset(ZONE.getSOA()));
    assertThatThrownBy(iterator::remove).hasMessageContaining("remove SOA");
  }

  @Test
  void iteratorRemoveAxfrSOAFails() {
    Iterator<RRset> iterator = ZONE.AXFR();
    while (iterator.hasNext()) {
      iterator.next();
    }

    assertThatThrownBy(iterator::remove).hasMessageContaining("remove SOA");
  }

  @Test
  void iteratorRemoveNSFails() {
    Iterator<RRset> iterator = ZONE.iterator();
    assertThat(iterator).isNotNull();
    assertThat(iterator.hasNext()).isTrue();
    assertThat(iterator.next()).isEqualTo(new RRset(ZONE.getSOA()));
    assertThat(iterator.hasNext()).isTrue();
    assertThat(iterator.next()).isEqualTo(ZONE.getNS());
    assertThatThrownBy(iterator::remove).hasMessageContaining("remove all NS");
  }

  @Test
  void iteratorRemoveNoNextFails() {
    assertThatThrownBy(ZONE.iterator()::remove)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Not at");
  }

  @Test
  void iteratorRemoveASucceeds() {
    Iterator<RRset> it = ZONE.iterator();
    it.next(); // SOA
    it.next(); // NS
    it.next(); // A
    it.remove();
    assertThat(ZONE.findExactMatch(A_1_TEST.getName(), Type.A)).isNull();
  }

  @Test
  void iteratorNextAfterLastFails() {
    Iterator<RRset> iterator = ZONE.iterator();
    while (iterator.hasNext()) {
      iterator.next();
    }

    assertThatThrownBy(iterator::next)
        .isInstanceOf(NoSuchElementException.class)
        .hasMessageContaining("No more elements");
  }

  @Test
  void isSerializable() throws IOException, ClassNotFoundException {
    ByteArrayOutputStream oms = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(oms);
    oos.writeObject(ZONE);
    byte[] zoneData = oms.toByteArray();
    ByteArrayInputStream ims = new ByteArrayInputStream(zoneData);
    ObjectInputStream ois = new ObjectInputStream(ims);
    Zone z = (Zone) ois.readObject();
    assertThat(z.getSOA()).isEqualTo(SOA1);
    assertThat(z.findExactMatch(ZONE.getOrigin(), Type.SOA)).first().isEqualTo(SOA1);
    assertDoesNotThrow(
        () -> z.addRecord(A_1_TEST.withName(new Name("some-other-name", ZONE.getOrigin()))));
  }

  /** A wildcard must not synthesize below an existing (empty non-terminal) closer encloser. */
  @Test
  void wildcardClosestEncloserTwoTypes() throws Exception {
    Record aWildcard =
        Record.fromString(
            Name.fromConstantString("*.example."), Type.A, DClass.IN, 3600, "192.0.2.1", Name.root);
    Record txtWildcard =
        Record.fromString(aWildcard.getName(), Type.TXT, DClass.IN, 3600, "test-data", Name.root);
    Record aEnt =
        Record.fromString(
            Name.fromConstantString("x.sub.example."),
            Type.A,
            DClass.IN,
            3600,
            "192.0.2.1",
            Name.root);
    Record txtEnt =
        Record.fromString(aEnt.getName(), Type.A, DClass.IN, 3600, "192.0.2.1", Name.root);
    Zone zone = new Zone(ZONE_NAME, SOA1, NS1, aWildcard, txtWildcard, aEnt, txtEnt);

    SetResponse nxA = zone.findRecords(Name.fromConstantString("y.sub.example."), Type.A);
    assertThat(nxA.isNXDOMAIN())
        .as("Wildcard must not synthesize from " + aWildcard.getName())
        .isTrue();

    SetResponse nxTxt = zone.findRecords(Name.fromConstantString("y.sub.example."), Type.TXT);
    assertThat(nxTxt.isNXDOMAIN())
        .as("Wildcard must not synthesize from " + aWildcard.getName())
        .isTrue();

    Name entName = new Name(aEnt.getName(), 1);
    SetResponse entA = zone.findRecords(entName, Type.A);
    assertThat(entA.isNXRRSET()).as("Must have an ENT at " + entName).isTrue();
    SetResponse entTxt = zone.findRecords(entName, Type.A);
    assertThat(entTxt.isNXRRSET()).as("Must have an ENT at " + entName).isTrue();
  }

  /** A wildcard must not synthesize below an existing (empty non-terminal) closer encloser. */
  @Test
  void wildcardClosestEncloserOneType() throws Exception {
    Record aWildcard =
        Record.fromString(
            Name.fromConstantString("*.example."), Type.A, DClass.IN, 3600, "192.0.2.1", Name.root);
    Record aEnt =
        Record.fromString(
            Name.fromConstantString("x.sub.example."),
            Type.A,
            DClass.IN,
            3600,
            "192.0.2.1",
            Name.root);
    Zone zone = new Zone(ZONE_NAME, SOA1, NS1, aWildcard, aEnt);

    SetResponse nxA = zone.findRecords(Name.fromConstantString("y.sub.example."), Type.A);
    assertThat(nxA.isNXDOMAIN())
        .as("Wildcard must not synthesize from " + aWildcard.getName())
        .isTrue();

    Name entName = new Name(aEnt.getName(), 1);
    SetResponse entA = zone.findRecords(entName, Type.A);
    assertThat(entA.isNXRRSET()).as("Must have an ENT at " + entName).isTrue();
  }

  /** A query at an empty non-terminal must answer NODATA. */
  @Test
  void pinEmptyNonTerminal() throws Exception {
    Zone zone =
        new Zone(
            ZONE_NAME,
            SOA1,
            NS1,
            Record.fromString(
                Name.fromConstantString("x.sub.example."),
                Type.A,
                DClass.IN,
                3600,
                "192.0.2.2",
                Name.root));
    SetResponse sr = zone.findRecords(Name.fromConstantString("sub.example."), Type.A);
    assertThat(sr.isNXRRSET()).as(sr.toString()).isTrue();
  }

  @Test
  void addRRsetAfterEmptyNonTerminal() throws Exception {
    Record a =
        Record.fromString(
            Name.fromConstantString("sub.example."),
            Type.A,
            DClass.IN,
            3600,
            "192.0.2.2",
            Name.root);
    Zone zone = new Zone(ZONE_NAME, SOA1, NS1, a.withName(new Name("x", a.getName())));
    SetResponse sr = zone.findRecords(a.getName(), Type.A);
    assertThat(sr.isNXRRSET()).as(sr.toString()).isTrue();
    zone.addRecord(a);
    sr = zone.findRecords(a.getName(), Type.A);
    assertThat(sr.isNXRRSET()).as(sr.toString()).isFalse();
    assertThat(sr.isSuccessful()).as(sr.toString()).isTrue();
    assertThat(sr.answers())
        .hasSize(1)
        .first()
        .asInstanceOf(InstanceOfAssertFactories.ITERABLE)
        .containsExactly(a);
  }

  @Test
  void removeRRsetAddEmptyNonTerminalBackOneType() throws Exception {
    Record a =
        Record.fromString(
            Name.fromConstantString("sub.example."),
            Type.A,
            DClass.IN,
            3600,
            "192.0.2.2",
            Name.root);
    Zone zone = new Zone(ZONE_NAME, SOA1, NS1, a.withName(new Name("x", a.getName())), a);
    SetResponse sr = zone.findRecords(a.getName(), Type.A);
    assertThat(sr.isNXRRSET()).as(sr.toString()).isFalse();
    assertThat(sr.isSuccessful()).as(sr.toString()).isTrue();

    zone.removeRRset(a.getName(), Type.A);
    sr = zone.findRecords(a.getName(), Type.A);
    assertThat(sr.isNXRRSET()).as(sr.toString()).isTrue();
    assertThat(sr.answers()).isNull();
  }

  @Test
  void removeRRsetAddEmptyNonTerminalBackTwoTypes() throws Exception {
    Record a =
        Record.fromString(
            Name.fromConstantString("sub.example."),
            Type.A,
            DClass.IN,
            3600,
            "192.0.2.2",
            Name.root);
    Record txt = Record.fromString(a.getName(), Type.TXT, DClass.IN, 3600, "192.0.2.2", Name.root);
    Zone zone =
        new Zone(
            ZONE_NAME,
            SOA1,
            NS1,
            a.withName(new Name("x", a.getName())),
            a,
            txt.withName(new Name("x", a.getName())),
            txt);
    SetResponse srA = zone.findRecords(a.getName(), Type.A);
    assertThat(srA.isNXRRSET()).as(srA.toString()).isFalse();
    assertThat(srA.isSuccessful()).as(srA.toString()).isTrue();

    SetResponse srTxt = zone.findRecords(txt.getName(), Type.TXT);
    assertThat(srTxt.isNXRRSET()).as(srTxt.toString()).isFalse();
    assertThat(srTxt.isSuccessful()).as(srTxt.toString()).isTrue();

    zone.removeRRset(a.getName(), Type.A);

    srA = zone.findRecords(a.getName(), Type.A);
    assertThat(srA.isNXRRSET()).as(srA.toString()).isTrue();
    assertThat(srA.answers()).isNull();

    srTxt = zone.findRecords(txt.getName(), Type.TXT);
    assertThat(srTxt.isNXRRSET()).as(srTxt.toString()).isFalse();
    assertThat(srTxt.isSuccessful()).isTrue();
    assertThat(srTxt.answers())
        .hasSize(1)
        .first()
        .asInstanceOf(InstanceOfAssertFactories.ITERABLE)
        .containsExactly(txt);

    zone.removeRRset(txt.getName(), Type.TXT);

    srA = zone.findRecords(a.getName(), Type.A);
    assertThat(srA.isNXRRSET()).as(srA.toString()).isTrue();
    assertThat(srA.answers()).isNull();

    srTxt = zone.findRecords(txt.getName(), Type.TXT);
    assertThat(srTxt.isNXRRSET()).as(srTxt.toString()).isTrue();
    assertThat(srTxt.isSuccessful()).isFalse();
  }

  private static List<RRset> listOf(RRset... rrsets) {
    return Stream.of(rrsets).collect(Collectors.toList());
  }

  private static List<RRset> oneRRset(Record... r) {
    return Collections.singletonList(new RRset(r));
  }
}

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

import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ZoneTest {
  private Name ZONE_NAME;
  private SOARecord SOA1;
  private SOARecord SOA2;
  private NSRecord NS1;
  private NSRecord NS2;
  private ARecord A_UNIQUE;
  private ARecord A_TEST;
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
    A_TEST = new ARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, localhost4);
    AAAA_1_TEST = new AAAARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, localhost6a);
    AAAA_2_TEST = new AAAARecord(new Name("test", ZONE_NAME), DClass.IN, 3600, localhost6b);
    A_WILD =
        new ARecord(
            new Name("*.wild", ZONE_NAME), DClass.IN, 3600, InetAddress.getByName("127.0.0.2"));
    TXT_WILD = new TXTRecord(new Name("*.wild", ZONE_NAME), DClass.IN, 3600, "sometext");

    Record[] zoneRecords =
        new Record[] {
          SOA1, NS1, NS2, A_UNIQUE, A_TEST, AAAA_1_TEST, AAAA_2_TEST, A_WILD, TXT_WILD,
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
    assertThat(ZONE.findExactMatch(A_TEST.getName(), Type.A)).isNotNull().containsExactly(A_TEST);
  }

  @Test
  void exactNameAnyThrow() {
    assertThatThrownBy(() -> ZONE.findExactMatch(A_TEST.getName(), Type.ANY))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("type ANY");
  }

  @Test
  void findNameExistingALookup() {
    SetResponse resp = ZONE.findRecords(A_TEST.getName(), Type.A);
    assertEquals(oneRRset(A_TEST), resp.answers());
  }

  @Test
  void findNameNXRRsetLookup() {
    SetResponse resp = ZONE.findRecords(A_TEST.getName(), Type.TXT);
    assertEquals(SetResponse.ofType(SetResponseType.NXRRSET), resp);
  }

  @Test
  void findNameTwoAaaaLookup() {
    SetResponse resp = ZONE.findRecords(AAAA_1_TEST.getName(), Type.AAAA);
    assertEquals(oneRRset(AAAA_1_TEST, AAAA_2_TEST), resp.answers());
  }

  @Test
  void findNameAnyLookup() {
    SetResponse resp = ZONE.findRecords(A_TEST.getName(), Type.ANY);
    assertTrue(resp.isSuccessful());
    assertEquals(listOf(new RRset(A_TEST), new RRset(AAAA_1_TEST, AAAA_2_TEST)), resp.answers());
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
    assertThat(resp.answers()).containsExactly(new RRset(TXT_WILD.withName(testName)));
  }

  @Test
  void findWildNameNonExistingMxLookup() {
    SetResponse resp =
        ZONE.findRecords(Name.fromConstantString("undefined.wild.example."), Type.MX);
    assertTrue(resp.isNXDOMAIN());
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
    assertThrows(IllegalArgumentException.class, () -> new Zone(null, (String) null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(null, (Record[]) null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(Name.root, (String) null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(Name.root, (Record[]) null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(null, "some-file.dns"));
    assertThrows(IllegalArgumentException.class, () -> new Zone(null, new Record[0]));
    assertThrows(IllegalArgumentException.class, () -> new Zone(null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(null, DClass.IN, null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(Name.root, DClass.IN, null));
    assertThrows(IllegalArgumentException.class, () -> new Zone(null, DClass.IN, "localhost"));
    assertThrows(InvalidDClassException.class, () -> new Zone(Name.root, -1, "localhost"));
  }

  @Test
  void ctorMissingRecords() {
    assertThrows(IOException.class, () -> new Zone(Name.root, new Record[0]));
    assertThrows(IOException.class, () -> new Zone(Name.root, new Record[] {A_TEST}));
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
  void addRecord() throws TextParseException {
    Name n = new Name("something", ZONE_NAME);
    assertNull(ZONE.findExactMatch(n, Type.A));
    ZONE.addRecord(A_TEST.withName(n));
    assertNotNull(ZONE.findExactMatch(n, Type.A));
  }

  @Test
  void addRecordExistingName() {
    Name n = A_TEST.getName();
    assertNotNull(ZONE.findExactMatch(n, Type.A));
    assertNull(ZONE.findExactMatch(n, Type.MX));
    MXRecord mx = new MXRecord(n, DClass.IN, 3600, 1, Name.root);
    ZONE.addRecord(mx);
    assertThat(ZONE.findExactMatch(n, Type.MX)).isNotNull().containsExactly(mx);
  }

  @Test
  void addRecordExistingSet() {
    Name n = A_TEST.getName();
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(A_TEST);
    ARecord a2 = new ARecord(n, DClass.IN, 3600, new byte[4]);
    ZONE.addRecord(a2);
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(A_TEST, a2);
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
    assertNotNull(ZONE.findExactMatch(A_TEST.getName(), Type.A));
    ZONE.removeRecord(A_TEST);
    assertNull(ZONE.findExactMatch(A_TEST.getName(), Type.A));
  }

  @Test
  void addRRset() throws TextParseException {
    Name n = new Name("something", ZONE_NAME);
    assertNull(ZONE.findExactMatch(n, Type.A));
    ZONE.addRRset(new RRset(A_TEST.withName(n)));
    assertNotNull(ZONE.findExactMatch(n, Type.A));
  }

  @Test
  void addRRsetExistingName() {
    Name n = A_TEST.getName();
    assertNotNull(ZONE.findExactMatch(n, Type.A));
    assertNull(ZONE.findExactMatch(n, Type.MX));
    MXRecord mx = new MXRecord(n, DClass.IN, 3600, 1, Name.root);
    ZONE.addRRset(new RRset(mx));
    assertThat(ZONE.findExactMatch(n, Type.MX)).isNotNull().containsExactly(mx);
  }

  @Test
  void addRRsetExistingSet() {
    Name n = A_TEST.getName();
    assertThat(ZONE.findExactMatch(n, Type.A)).isNotNull().containsExactly(A_TEST);
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
    assertThatThrownBy(() -> ZONE.addRecord(A_TEST.withName(Name.root)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("subdomain");
  }

  @Test
  void addRRsetOutOfZone() {
    assertThatThrownBy(() -> ZONE.addRRset(new RRset(A_TEST.withName(Name.root))))
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
    assertThatThrownBy(() -> ZONE.addRRset(new RRset(newSoa)))
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
    assertThatThrownBy(() -> ZONE.addRRset(new RRset(SOA1, SOA2)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exactly 1 SOA");
    assertThat(ZONE.getSOA()).isNotNull().isEqualTo(SOA1);
  }

  @Test
  void removeSOARecord() {
    assertThatThrownBy(() -> ZONE.removeRecord(ZONE.getSOA()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("remove SOA");
    RRset soa = ZONE.findExactMatch(ZONE_NAME, Type.SOA);
    assertThat(soa).isNotNull().containsExactly(ZONE.getSOA());
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
    Name n = A_TEST.getName();
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
            new RRset(A_TEST),
            new RRset(AAAA_1_TEST, AAAA_2_TEST),
            new RRset(A_UNIQUE),
            new RRset(A_WILD),
            new RRset(TXT_WILD));
  }

  @Test
  void iteratorHasAllInOrderWithNamesAtOrigin() {
    MXRecord mx = new MXRecord(ZONE_NAME, DClass.IN, 3600, 1, A_TEST.getName());
    ZONE.addRecord(mx);
    assertThat(ZONE)
        .hasSize(8)
        .containsExactly(
            new RRset(SOA1),
            new RRset(NS1, NS2),
            new RRset(mx),
            new RRset(A_TEST),
            new RRset(AAAA_1_TEST, AAAA_2_TEST),
            new RRset(A_UNIQUE),
            new RRset(A_WILD),
            new RRset(TXT_WILD));
  }

  @Test
  void iteratorHasAllInOrderWithNamesAtOriginForAXFR() {
    MXRecord mx = new MXRecord(ZONE_NAME, DClass.IN, 3600, 1, A_TEST.getName());
    ZONE.addRecord(mx);
    assertThat(ZONE.AXFR())
        .toIterable()
        .hasSize(9)
        .containsExactly(
            new RRset(SOA1),
            new RRset(NS1, NS2),
            new RRset(mx),
            new RRset(A_TEST),
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
    assertThat(aSet).containsExactly(A_TEST);
    aSet.deleteRR(aSet.first());
    assertThat(aSet).isEmpty();
    assertThat(ZONE.findExactMatch(A_TEST.getName(), Type.A)).hasSize(1);
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
    assertThat(ZONE.findExactMatch(A_TEST.getName(), Type.A)).isNull();
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

  private static List<RRset> listOf(RRset... rrsets) {
    return Stream.of(rrsets).collect(Collectors.toList());
  }

  private static List<RRset> oneRRset(Record... r) {
    return Collections.singletonList(new RRset(r));
  }
}

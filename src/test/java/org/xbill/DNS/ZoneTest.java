// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ZoneTest {
  private Zone zone;

  @BeforeEach
  void beforeEach() throws IOException {
    Name nameZone = new Name("example.");
    InetAddress localhost4 = InetAddress.getByName("127.0.0.1");
    InetAddress localhost6a = InetAddress.getByName("::1");
    InetAddress localhost6b = InetAddress.getByName("::2");
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
          new ARecord(new Name("test", nameZone), DClass.IN, 3600, localhost4),
          new AAAARecord(new Name("test", nameZone), DClass.IN, 3600, localhost6a),
          new AAAARecord(new Name("test", nameZone), DClass.IN, 3600, localhost6b),
          new ARecord(new Name("*", nameZone), DClass.IN, 3600, localhost4),
          new TXTRecord(new Name("*", nameZone), DClass.IN, 3600, "sometext")
        };
    zone = new Zone(nameZone, zoneRecords);
  }

  @Test
  void exactNameExistingALookup() {
    Name testName = Name.fromConstantString("test.example.");
    SetResponse resp = zone.findRecords(testName, Type.A);
    assertEquals(testName, resp.answers().get(0).first().getName());
    assertEquals(Type.A, resp.answers().get(0).first().getType());
  }

  @Test
  void exactNameTwoAaaaLookup() {
    Name testName = Name.fromConstantString("test.example.");
    SetResponse resp = zone.findRecords(testName, Type.AAAA);
    assertEquals(2, resp.answers().get(0).rrs().size());
    assertEquals(testName, resp.answers().get(0).first().getName());
  }

  @Test
  void exactNameAnyLookup() {
    Name testName = Name.fromConstantString("test.example.");
    SetResponse resp = zone.findRecords(testName, Type.ANY);
    assertTrue(resp.isSuccessful());
    assertEquals(2, resp.answers().size());
    assertEquals(testName, resp.answers().get(0).getName());
    assertEquals(
        1,
        resp.answers().stream()
            .filter(rrset -> rrset.getType() == Type.A)
            .findFirst()
            .orElseThrow(() -> new RuntimeException("A rrset not found"))
            .rrs()
            .size());
    assertEquals(
        2,
        resp.answers().stream()
            .filter(rrset -> rrset.getType() == Type.AAAA)
            .findFirst()
            .orElseThrow(() -> new RuntimeException("AAAA rrset not found"))
            .rrs()
            .size());
  }

  @Test
  void wildNameExistingALookup() {
    Name testName = Name.fromConstantString("undefined.example.");
    SetResponse resp = zone.findRecords(testName, Type.A);
    assertEquals(testName, resp.answers().get(0).first().getName());
    assertEquals(Type.A, resp.answers().get(0).first().getType());
  }

  @Test
  void wildNameExistingTxtLookup() {
    Name testName = Name.fromConstantString("undefined.example.");
    SetResponse resp = zone.findRecords(testName, Type.TXT);
    assertEquals(testName, resp.answers().get(0).first().getName());
    assertEquals(Type.TXT, resp.answers().get(0).first().getType());
  }

  @Test
  void wildNameNonExistingMxLookup() {
    SetResponse resp = zone.findRecords(Name.fromConstantString("undefined.example."), Type.MX);
    assertTrue(resp.isNXDOMAIN());
  }

  @Test
  void wildNameAnyLookup() {
    Name testName = Name.fromConstantString("undefined.example.");
    SetResponse resp = zone.findRecords(testName, Type.ANY);
    assertTrue(resp.isSuccessful());
    assertEquals(2, resp.answers().size());
    assertEquals(testName, resp.answers().get(0).getName());
    assertTrue(resp.answers().stream().anyMatch(rrset -> rrset.getType() == Type.A));
    assertTrue(resp.answers().stream().anyMatch(rrset -> rrset.getType() == Type.TXT));
  }
}

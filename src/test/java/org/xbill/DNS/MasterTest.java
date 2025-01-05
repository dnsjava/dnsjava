// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.DNSSECException;

class MasterTest {

  /**
   * Parse the <a href="https://www.internic.net/domain/root.zone">root zone file</a> to validate
   * that we understand all record types.
   */
  @Test
  void testRootZoneFile() throws IOException, DNSSECException {
    List<Record> records = new ArrayList<>(26000);
    Map<String, RRset> rrSets = new HashMap<>(13000);
    try (Master master = new Master(MasterTest.class.getResourceAsStream("/root.zone"))) {
      Record r;
      while ((r = master.nextRecord()) != null) {
        records.add(r);
        String key =
            r.getName()
                + "/"
                + (r.getType() == Type.RRSIG ? ((RRSIGRecord) r).getTypeCovered() : r.getType());
        RRset set = rrSets.computeIfAbsent(key, n -> new RRset());
        set.addRR(r);
        assertFalse(r.getClass().isInstance(EmptyRecord.class), "EmptyRecord type check");
        assertNotEquals(Integer.toString(r.getType()), Type.string(r.getType()));
      }
    }

    assertEquals(25097, records.size());

    // Test the signatures
    DNSKEYRecord[] keys =
        records.stream()
            .filter(r -> r.getName().equals(Name.root) && r.getType() == Type.DNSKEY)
            .map(r -> (DNSKEYRecord) r)
            .toArray(DNSKEYRecord[]::new);
    for (RRset set : rrSets.values()) {
      for (RRSIGRecord sig : set.sigs()) {
        int verifyCount = 0;
        for (DNSKEYRecord key : keys) {
          if (key.getFootprint() == sig.getFootprint()) {
            DNSSEC.verify(set, sig, key, Instant.parse("2023-11-05T19:50:00Z"));
            verifyCount++;
          }
        }
        assertEquals(set.sigs().size(), verifyCount);
      }
    }
  }

  @Test
  void nextRecord() throws IOException {
    Name exampleComName = Name.fromConstantString("example.com.");
    try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
      master.expandGenerate(false);
      Record rr = master.nextRecord();
      assertEquals(Type.SOA, rr.getType());
      rr = master.nextRecord();
      assertEquals(Type.NS, rr.getType());
      rr = master.nextRecord();
      assertEquals(Type.MX, rr.getType());

      rr = master.nextRecord();
      // test special '@' resolves name correctly
      assertEquals(exampleComName, rr.getName());

      rr = master.nextRecord();
      // test relative host become absolute
      assertEquals(Name.fromConstantString("mail3.example.com."), rr.getAdditionalName());

      rr = master.nextRecord();
      assertEquals(Type.A, rr.getType());

      rr = master.nextRecord();
      assertEquals(Type.AAAA, rr.getType());

      rr = master.nextRecord();
      assertEquals(Type.CNAME, rr.getType());

      rr = master.nextRecord();
      assertNull(rr);
      // $GENERATE directive is last in zonefile
      assertTrue(master.generators().hasNext());
    }
  }

  @Test
  void includeDirective() throws IOException, URISyntaxException {
    try (Master master =
        new Master(
            Paths.get(MasterTest.class.getResource("/zonefileIncludeDirective").toURI())
                .toString())) {
      Record rr = master.nextRecord();
      assertEquals(Type.SOA, rr.getType());
    }
  }

  @Test
  void includeDirectiveComment() throws IOException, URISyntaxException {
    try (Master master =
        new Master(
            Paths.get(MasterTest.class.getResource("/zonefileIncludeDirectiveComment").toURI())
                .toString())) {
      Record rr = master.nextRecord();
      assertEquals(Type.SOA, rr.getType());
    }
  }

  @Test
  void relativeIncludeDirectiveViaStream() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirective");
        Master m = new Master(is)) {
      assertThrows(TextParseException.class, m::nextRecord);
    }
  }

  @Test
  void includeDirectiveDisabled() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirective");
        Master m = new Master(is)) {
      m.disableIncludes();
      assertNull(m.nextRecord());
    }
  }

  @Test
  void includeDirectiveDisabledStrict() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirective");
        Master m = new Master(is)) {
      m.disableIncludes(true);
      assertThrows(TextParseException.class, m::nextRecord);
    }
  }

  @Test
  void includeDirectiveDisabledComment() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirectiveComment");
        Master m = new Master(is)) {
      m.disableIncludes();
      assertNull(m.nextRecord());
    }
  }

  @Test
  void expandGenerated() throws IOException {
    try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
      master.expandGenerate(true);
      // until we get to the generator directive, it's empty
      assertFalse(master.generators().hasNext());
      Record rr = skipTo(master, Type.PTR);
      assertTrue(master.generators().hasNext());
      assertEquals(Type.PTR, rr.getType());
      assertEquals(
          Name.fromConstantString("host-1.dsl.example.com."), ((PTRRecord) rr).getTarget());
    }
  }

  @Test
  void invalidGenRange() {
    try (Master master = new Master(new ByteArrayInputStream("$GENERATE 3-1".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("Invalid $GENERATE range specifier: 3-1"));
    }
  }

  @Test
  void invalidGenType() {
    try (Master master =
        new Master(
            new ByteArrayInputStream(
                "$TTL 1h\n$GENERATE 1-3 example.com. MX 10 mail.example.com.".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("$GENERATE does not support MX records"));
    }
  }

  @Test
  void invalidGenerateRangeSpecifier() {
    try (Master master = new Master(new ByteArrayInputStream("$GENERATE 1to20".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("Invalid $GENERATE range specifier"));
    }
  }

  @Test
  void invalidDirective() {
    try (Master master = new Master(new ByteArrayInputStream("$INVALID".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("Invalid directive: $INVALID"));
    }
  }

  @Test
  void missingTTL() {
    try (Master master = new Master(new ByteArrayInputStream("example.com. IN NS ns".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("missing TTL"));
    }
  }

  @Test
  void invalidType() {
    try (Master master =
        new Master(new ByteArrayInputStream("example.com. IN INVALID".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("Invalid type"));
    }
  }

  @Test
  void noOwner() {
    try (Master master = new Master(new ByteArrayInputStream(" \n ^".getBytes()))) {
      TextParseException thrown = assertThrows(TextParseException.class, master::nextRecord);
      assertTrue(thrown.getMessage().contains("no owner"));
    }
  }

  @Test
  void invalidOriginNotAbsolute_ctorInputStream() {
    RelativeNameException thrown =
        assertThrows(
            RelativeNameException.class,
            () -> new Master((InputStream) null, Name.fromConstantString("notabsolute")));
    assertTrue(thrown.getMessage().contains("'notabsolute' is not an absolute name"));
  }

  @Test
  void invalidOriginNotAbsolute_ctorString() {
    RelativeNameException thrown =
        assertThrows(
            RelativeNameException.class,
            () -> new Master("zonefileEx1", Name.fromConstantString("notabsolute")));
    assertTrue(thrown.getMessage().contains("'notabsolute' is not an absolute name"));
  }

  private Record skipTo(Master master, int type) throws IOException {
    Record r;
    do {
      r = master.nextRecord();
    } while (r != null && r.getType() != type);
    return r;
  }
}

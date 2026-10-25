// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

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
        assertThat(r.getClass().isInstance(EmptyRecord.class))
            .as("EmptyRecord type check")
            .isFalse();
        assertThat(Type.string(r.getType())).isNotEqualTo(Integer.toString(r.getType()));
      }
    }

    assertThat(records).hasSize(25097);

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
        assertThat(verifyCount).isEqualTo(set.sigs().size());
      }
    }
  }

  @Test
  void nextRecord() throws IOException {
    Name exampleComName = Name.fromConstantString("example.com.");
    try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
      master.expandGenerate(false);
      Record rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.SOA);
      rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.NS);
      rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.MX);

      rr = master.nextRecord();
      // test special '@' resolves name correctly
      assertThat(rr.getName()).isEqualTo(exampleComName);

      rr = master.nextRecord();
      // test relative host become absolute
      assertThat(rr.getAdditionalName()).isEqualTo(Name.fromConstantString("mail3.example.com."));

      rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.A);

      rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.AAAA);

      rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.CNAME);

      rr = master.nextRecord();
      assertThat(rr).isNull();
      // $GENERATE directive is last in zonefile
      assertThat(master.generators().hasNext()).isTrue();
    }
  }

  @Test
  void includeDirective() throws IOException, URISyntaxException {
    try (Master master =
        new Master(
            Paths.get(MasterTest.class.getResource("/zonefileIncludeDirective").toURI())
                .toString())) {
      Record rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.SOA);
    }
  }

  @Test
  void includeDirectiveComment() throws IOException, URISyntaxException {
    try (Master master =
        new Master(
            Paths.get(MasterTest.class.getResource("/zonefileIncludeDirectiveComment").toURI())
                .toString())) {
      Record rr = master.nextRecord();
      assertThat(rr.getType()).isEqualTo(Type.SOA);
    }
  }

  @Test
  void relativeIncludeDirectiveViaStream() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirective");
        Master m = new Master(is)) {
      assertThatExceptionOfType(TextParseException.class).isThrownBy(m::nextRecord);
    }
  }

  @Test
  void includeDirectiveDisabled() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirective");
        Master m = new Master(is)) {
      m.disableIncludes();
      assertThat(m.nextRecord()).isNull();
    }
  }

  @Test
  void includeDirectiveDisabledStrict() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirective");
        Master m = new Master(is)) {
      m.disableIncludes(true);
      assertThatExceptionOfType(TextParseException.class).isThrownBy(m::nextRecord);
    }
  }

  @Test
  void includeDirectiveDisabledComment() throws IOException {
    try (InputStream is = MasterTest.class.getResourceAsStream("/zonefileIncludeDirectiveComment");
        Master m = new Master(is)) {
      m.disableIncludes();
      assertThat(m.nextRecord()).isNull();
    }
  }

  @Test
  void expandGenerated() throws IOException {
    try (Master master = new Master(MasterTest.class.getResourceAsStream("/zonefileEx1"))) {
      master.expandGenerate(true);
      // until we get to the generator directive, it's empty
      assertThat(master.generators().hasNext()).isFalse();
      Record rr = skipTo(master, Type.PTR);
      assertThat(master.generators().hasNext()).isTrue();
      assertThat(rr.getType()).isEqualTo(Type.PTR);
      assertThat(((PTRRecord) rr).getTarget())
          .isEqualTo(Name.fromConstantString("host-1.dsl.example.com."));
    }
  }

  @Test
  void invalidGenRange() {
    try (Master master = new Master(new ByteArrayInputStream("$GENERATE 3-1".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("Invalid $GENERATE range specifier: 3-1");
    }
  }

  @Test
  void invalidGenType() {
    try (Master master =
        new Master(
            new ByteArrayInputStream(
                "$TTL 1h\n$GENERATE 1-3 example.com. MX 10 mail.example.com.".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("$GENERATE does not support MX records");
    }
  }

  @Test
  void invalidGenerateRangeSpecifier() {
    try (Master master = new Master(new ByteArrayInputStream("$GENERATE 1to20".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("Invalid $GENERATE range specifier");
    }
  }

  @Test
  void invalidDirective() {
    try (Master master = new Master(new ByteArrayInputStream("$INVALID".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("Invalid directive: $INVALID");
    }
  }

  @Test
  void missingTTL() {
    try (Master master = new Master(new ByteArrayInputStream("example.com. IN NS ns".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("missing TTL");
    }
  }

  @Test
  void invalidType() {
    try (Master master =
        new Master(new ByteArrayInputStream("example.com. IN INVALID".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("Invalid type");
    }
  }

  @Test
  void noOwner() {
    try (Master master = new Master(new ByteArrayInputStream(" \n ^".getBytes()))) {
      TextParseException thrown =
          assertThatExceptionOfType(TextParseException.class)
              .isThrownBy(master::nextRecord)
              .actual();
      assertThat(thrown.getMessage()).contains("no owner");
    }
  }

  @Test
  void invalidOriginNotAbsolute_ctorInputStream() {
    Name notAbsoluteName = Name.fromConstantString("notabsolute");
    RelativeNameException thrown =
        assertThatExceptionOfType(RelativeNameException.class)
            .isThrownBy(() -> new Master((InputStream) null, notAbsoluteName))
            .actual();
    assertThat(thrown.getMessage()).contains("'notabsolute' is not an absolute name");
  }

  @Test
  void invalidOriginNotAbsolute_ctorString() {
    Name notAbsoluteName = Name.fromConstantString("notabsolute");
    RelativeNameException thrown =
        assertThatExceptionOfType(RelativeNameException.class)
            .isThrownBy(() -> new Master("zonefileEx1", notAbsoluteName))
            .actual();
    assertThat(thrown.getMessage()).contains("'notabsolute' is not an absolute name");
  }

  private Record skipTo(Master master, int type) throws IOException {
    Record r;
    do {
      r = master.nextRecord();
    } while (r != null && r.getType() != type);
    return r;
  }
}

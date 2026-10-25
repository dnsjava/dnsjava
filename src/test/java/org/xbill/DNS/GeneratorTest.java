// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

public class GeneratorTest {
  private static final Name origin = Name.fromConstantString("example.com.");

  @ParameterizedTest
  @ValueSource(
      ints = {
        Type.PTR,
        Type.CNAME,
        Type.DNAME,
        Type.A,
        Type.AAAA,
        Type.NS,
      })
  void testSupportedType(int type) {
    assertThat(Generator.supportedType(type)).as(Type.string(type)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        Type.MX, Type.SOA,
      })
  void testUnsupportedType(int type) {
    assertThat(Generator.supportedType(type)).as(Type.string(type)).isFalse();
  }

  @Test
  void testInvalidType() {
    assertThatThrownBy(() -> Generator.supportedType(-1)).isInstanceOf(InvalidTypeException.class);
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "-1,-10,1",
        "10,5,1",
        "0,10,0",
        "0,10,-1",
      })
  void testConstructor_InvalidRange(int start, int end, int step) {
    assertThatThrownBy(
            () ->
                new Generator(
                    start, end, step, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", Name.root))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void testConstructor_UnsupportedType() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new Generator(0, 10, 1, "host$", Type.MX, DClass.IN, 3600, "1.2.3.$", Name.root));
  }

  @Test
  void testConstructor_InvalidDClass() {
    assertThrows(
        InvalidDClassException.class,
        () -> new Generator(0, 10, 1, "host$", Type.A, -1, 3600, "1.2.3.$", Name.root));
  }

  @Test
  void testNextRecord() throws IOException {
    Generator g = new Generator(1, 3, 1, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin);

    Record r1 = g.nextRecord();
    assertNotNull(r1);
    assertEquals("host1.example.com.", r1.getName().toString());
    assertEquals("1.2.3.1", ((ARecord) r1).getAddress().getHostAddress());

    Record r2 = g.nextRecord();
    assertNotNull(r2);
    assertEquals("host2.example.com.", r2.getName().toString());
    assertEquals("1.2.3.2", ((ARecord) r2).getAddress().getHostAddress());

    Record r3 = g.nextRecord();
    assertNotNull(r3);
    assertEquals("host3.example.com.", r3.getName().toString());
    assertEquals("1.2.3.3", ((ARecord) r3).getAddress().getHostAddress());

    assertNull(g.nextRecord());
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "1|1|1|host-$|host-1.example.com.",
        "1|1|1|host-$.xyz|host-1.xyz.example.com.",
        "15|15|1|host-${1,3,x}|host-010.example.com.",
        "15|15|1|host-${1,3,x}.xyz|host-010.xyz.example.com.",
        "15|15|1|host-${1,3,X}|host-010.example.com.",
        "15|15|1|host-${1,3,X}.xyz|host-010.xyz.example.com.",
        "30|30|1|host-${1,1,x}|host-1f.example.com.",
        "30|30|1|host-${1,1,x}.xyz|host-1f.xyz.example.com.",
        "30|30|1|host-${1,1,X}|host-1F.example.com.",
        "30|30|1|host-${1,1,X}.xyz|host-1F.xyz.example.com.",
        "7|7|1|host-${1,3,o}|host-010.example.com.",
        "7|7|1|host-${1,3,o}.xyz|host-010.xyz.example.com.",
        "7|7|1|host-${1,3,O}|host-010.example.com.",
        "7|7|1|host-${1,3,O}.xyz|host-010.xyz.example.com.",
      },
      delimiter = '|')
  void testSubstitution_Modifiers(int start, int end, int step, String namePattern, String expected)
      throws IOException {
    Generator g =
        new Generator(start, end, step, namePattern, Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertThat(r.getName()).hasToString(expected);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "host$$", "host\\$",
      })
  void testDollarEscapes(String namePatter) throws IOException {
    Generator g = new Generator(1, 1, 1, namePatter, Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertThat(r.getName()).hasToString("host\\$.example.com.");
  }

  @Test
  void testSubstitution_PlainDollar() throws IOException {
    Generator g = new Generator(1, 1, 1, "host$", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertThat(r.getName())
        .as("A single $ at the end of string should be treated as ${0}")
        .hasToString("host1.example.com.");
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "host${a}|invalid spec, unexpected character",
        "host${1,a}|invalid spec, unexpected character",
        "host${1,1,z}|invalid spec, unexpected character z for base",
        "host${1,1,d,1}|invalid spec, too many parts",
        "host${1,1,x|unexpected end of pattern",
        "host\\|invalid spec, unexpected end of pattern",
      },
      delimiter = '|')
  void testSubstitution_InvalidModifiers(String pattern, String exceptionMessage) {
    assertThatThrownBy(
            () ->
                new Generator(1, 1, 1, pattern, Type.A, DClass.IN, 3600, "1.2.3.1", origin)
                    .nextRecord())
        .isInstanceOf(TextParseException.class)
        .hasMessageContaining(exceptionMessage);
  }

  @Test
  void testSubstitution_NegativeOffset() throws IOException {
    Generator g =
        new Generator(10, 10, 1, "host${-1,1,d}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertEquals("host9.example.com.", r.getName().toString());

    // Test underflow
    Generator g2 =
        new Generator(5, 5, 1, "host${-10,1,d}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    assertThrows(TextParseException.class, g2::nextRecord);
  }

  @Test
  void testToString() {
    Generator g = new Generator(1, 10, 2, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin);
    String s = g.toString();
    assertEquals("$GENERATE 1-10/2 host$ 3600 IN A 1.2.3.$ ", s);
  }

  @Test
  void expand() throws IOException {
    int start = 1;
    int end = 3;
    int step = 1;
    Generator g =
        new Generator(start, end, step, "host$", Type.A, DClass.IN, 3600, "10.0.0.$", Name.root);

    List<ARecord> l = new ArrayList<>();
    for (int i = start; i <= end; i += step) {
      l.add(
          new ARecord(
              Name.fromConstantString("host" + i + "."),
              DClass.IN,
              3600,
              new byte[] {10, 0, 0, (byte) i}));
    }

    assertThat(g.expand()).containsExactlyElementsOf(l);
  }

  @Test
  void invalidGenWidth() {
    Generator g =
        new Generator(
            1, 1, 1, "host${0,4294967299,d}", Type.A, DClass.IN, 3600, "10.0.0.$", origin);
    assertThatThrownBy(g::expand)
        .isInstanceOf(TextParseException.class)
        .hasMessageContaining("exceeds");
  }

  /** $GENERATE modifiers with one or two fields ("${1}", "${1,3}") are valid. */
  @ParameterizedTest
  @CsvSource(
      value = {
        "host${1}|host2|10.0.0.$|10.0.0.1",
        "host${1}|host2|10.0.0.${1}|10.0.0.2",
        "host${1,3}|host002|10.0.0.$|10.0.0.1",
        "host${1,3}|host002|10.0.0.${1}|10.0.0.2",
      },
      delimiter = '|')
  void generatorShortModifiers(
      String namePattern, String expectedName, String rdataPattern, String expectedRdata)
      throws Exception {
    Record one =
        new Generator(1, 1, 1, namePattern, Type.A, DClass.IN, 3600, rdataPattern, origin)
            .nextRecord();
    assertThat(one.getName()).isEqualTo(new Name(expectedName, origin));
    assertThat(one.rrToString()).isEqualTo(expectedRdata);
  }

  @Test
  void nextRecord() throws IOException {
    int start = 1;
    int end = 3;
    int step = 1;
    Generator g =
        new Generator(start, end, step, "host$", Type.A, DClass.IN, 3600, "10.0.0.$", Name.root);

    List<ARecord> l = new ArrayList<>();
    for (int i = start; i <= end; i += step) {
      l.add(
          new ARecord(
              Name.fromConstantString("host" + i + "."),
              DClass.IN,
              3600,
              new byte[] {10, 0, 0, (byte) i}));
    }

    List<Record> l2 = new ArrayList<>();
    Record r;
    while ((r = g.nextRecord()) != null) {
      l2.add(r);
    }

    assertThat(l2).containsExactlyElementsOf(l);
  }
}

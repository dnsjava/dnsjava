package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class GeneratorTest {

  @Test
  void testSupportedType() {
    assertTrue(Generator.supportedType(Type.PTR));
    assertTrue(Generator.supportedType(Type.CNAME));
    assertTrue(Generator.supportedType(Type.DNAME));
    assertTrue(Generator.supportedType(Type.A));
    assertTrue(Generator.supportedType(Type.AAAA));
    assertTrue(Generator.supportedType(Type.NS));

    assertTrue(!Generator.supportedType(Type.MX));
    assertTrue(!Generator.supportedType(Type.SOA));

    assertThrows(InvalidTypeException.class, () -> Generator.supportedType(-1));
  }

  @Test
  void testConstructor_InvalidRange() {
    Name origin = Name.root;
    assertThrows(
        IllegalArgumentException.class,
        () -> new Generator(-1, 10, 1, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Generator(10, 5, 1, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Generator(0, 10, 0, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Generator(0, 10, -1, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin));
  }

  @Test
  void testConstructor_UnsupportedType() {
    Name origin = Name.root;
    assertThrows(
        IllegalArgumentException.class,
        () -> new Generator(0, 10, 1, "host$", Type.MX, DClass.IN, 3600, "1.2.3.$", origin));
  }

  @Test
  void testConstructor_InvalidDClass() {
    Name origin = Name.root;
    assertThrows(
        InvalidDClassException.class,
        () -> new Generator(0, 10, 1, "host$", Type.A, -1, 3600, "1.2.3.$", origin));
  }

  @Test
  void testNextRecord() throws IOException {
    Name origin = Name.fromConstantString("example.com.");
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

  @Test
  void testSubstitution_Modifiers() throws IOException {
    Name origin = Name.fromConstantString("example.com.");
    // ${offset,width,base}
    // offset=1, width=3, base=x
    Generator g =
        new Generator(15, 15, 1, "host${1,3,x}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    // 15 + 1 = 16. Hex 16 is 10. Width 3 -> 010.
    assertEquals("host010.example.com.", r.getName().toString());

    // Test Upper Case Hex
    g = new Generator(15, 15, 1, "host${1,3,X}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    r = g.nextRecord();
    assertEquals("host010.example.com.", r.getName().toString()); // 10 doesn't have letters.

    g = new Generator(30, 30, 1, "host${1,1,X}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    r = g.nextRecord();
    // 30 + 1 = 31. Hex 31 is 1f. X -> 1F.
    assertEquals("host1F.example.com.", r.getName().toString());

    // Test Octal
    g = new Generator(7, 7, 1, "host${1,3,o}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    r = g.nextRecord();
    // 7 + 1 = 8. Octal 8 is 10. Width 3 -> 010.
    assertEquals("host010.example.com.", r.getName().toString());
  }

  @Test
  void testSubstitution_LiteralDollar() throws IOException {
    Name origin = Name.fromConstantString("example.com.");
    Generator g = new Generator(1, 1, 1, "host$$", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertEquals("host\\$.example.com.", r.getName().toString());
  }

  @Test
  void testSubstitution_Escaped() throws IOException {
    Name origin = Name.fromConstantString("example.com.");
    Generator g = new Generator(1, 1, 1, "host\\$", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertEquals("host\\$.example.com.", r.getName().toString());
  }

  @Test
  void testSubstitution_PlainDollar() throws IOException {
    Name origin = Name.fromConstantString("example.com.");
    // A single $ at the end of string should be treated as literal $ by the current implementation
    // because it doesn't match $$, ${, and is not escaped.
    Generator g = new Generator(1, 1, 1, "host$", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertEquals("host1.example.com.", r.getName().toString());
  }

  @Test
  void testSubstitution_InvalidModifiers() {
    Name origin = Name.fromConstantString("example.com.");
    // Invalid offset (not a number)
    assertThrows(
        TextParseException.class,
        () ->
            new Generator(1, 1, 1, "host${a}", Type.A, DClass.IN, 3600, "1.2.3.1", origin)
                .nextRecord());
    // Invalid width (not a number)
    assertThrows(
        TextParseException.class,
        () ->
            new Generator(1, 1, 1, "host${1,a}", Type.A, DClass.IN, 3600, "1.2.3.1", origin)
                .nextRecord());
    // Invalid base
    assertThrows(
        TextParseException.class,
        () ->
            new Generator(1, 1, 1, "host${1,1,z}", Type.A, DClass.IN, 3600, "1.2.3.1", origin)
                .nextRecord());
    // Missing closing brace
    assertThrows(
        TextParseException.class,
        () ->
            new Generator(1, 1, 1, "host${1,1,x", Type.A, DClass.IN, 3600, "1.2.3.1", origin)
                .nextRecord());
    // Invalid escape at end
    assertThrows(
        TextParseException.class,
        () ->
            new Generator(1, 1, 1, "host\\", Type.A, DClass.IN, 3600, "1.2.3.1", origin)
                .nextRecord());
  }

  @Test
  void testSubstitution_NegativeOffset() throws IOException {
    Name origin = Name.fromConstantString("example.com.");
    Generator g =
        new Generator(10, 10, 1, "host${-1,1,d}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    Record r = g.nextRecord();
    assertEquals("host9.example.com.", r.getName().toString());

    // Test underflow
    Generator g2 =
        new Generator(5, 5, 1, "host${-10,1,d}", Type.A, DClass.IN, 3600, "1.2.3.1", origin);
    assertThrows(TextParseException.class, () -> g2.nextRecord());
  }

  @Test
  void testToString() {
    Name origin = Name.fromConstantString("example.com.");
    Generator g = new Generator(1, 10, 2, "host$", Type.A, DClass.IN, 3600, "1.2.3.$", origin);
    String s = g.toString();
    assertEquals("$GENERATE 1-10/2 host$ 3600 IN A 1.2.3.$ ", s);
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.xbill.DNS.ZoneMDRecord.Hash;
import org.xbill.DNS.utils.base16;

public class ZoneMDRecordTest {
  @ParameterizedTest
  @CsvSource({
    "1,48", "2,64",
  })
  void testKnownHashLengths(int alg, int len) {
    assertEquals(len, Hash.hashLength(alg));
  }

  @ParameterizedTest
  @CsvSource({
    "1,384", "2,512",
  })
  void testKnownHashNames(int alg, String suffix) {
    assertEquals("SHA" + suffix, Hash.string(alg));
  }

  @ParameterizedTest
  @CsvSource({
    "0,0,12", "1,0,12", "0,1,48", "0,2,64",
  })
  void testConstructorSuccess(int scheme, int hash, int digestSize) {
    ZoneMDRecord md =
        new ZoneMDRecord(
            Name.root, DClass.IN, 3600, 2147483648L, scheme, hash, new byte[digestSize]);
    assertNotNull(md);
    assertEquals(2147483648L, md.getSerial());
    assertEquals(scheme, md.getScheme());
    assertEquals(hash, md.getHashAlgorithm());
  }

  @ParameterizedTest
  @CsvSource({
    "-1,0,0,12",
    "4294967296,0,0,12",
    "2147483648,-1,0,12",
    "2147483648,257,0,12",
    "2147483648,0,-1,12",
    "2147483648,0,257,12",
    "2147483648,0,0,11",
    "2147483648,0,1,47",
    "2147483648,0,1,49",
    "2147483648,0,2,63",
    "2147483648,0,2,65",
  })
  void testConstructorFails(long serial, int scheme, int hash, int digestSize) {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ZoneMDRecord(
                Name.root, DClass.IN, 3600, serial, scheme, hash, new byte[digestSize]));
  }

  @ParameterizedTest
  @CsvSource({
    "2147483648,0,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,0,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE",
    "2147483648,0,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C",
    "2147483648,1,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,1,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE",
    "2147483648,1,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C",
  })
  void testFromWireSuccess(long serial, int scheme, int hash, String digest) {
    ZoneMDRecord md =
        new ZoneMDRecord(
            Name.root, DClass.IN, 3600, serial, scheme, hash, base16.fromString(digest));
    assertNotNull(md);
    assertEquals(2147483648L, md.getSerial());
    assertEquals(scheme, md.getScheme());
    assertEquals(hash, md.getHashAlgorithm());
  }

  @ParameterizedTest
  @CsvSource({
    "-1,0,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "4294967296,0,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,0,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C5D",
    "2147483648,0,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D",
    "2147483648,0,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFF",
    "2147483648,0,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057B",
    "2147483648,0,0,FEBE3D4CFEBEFEBE3D4CFE",
    "2147483648,-1,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,257,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,0,-1,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,0,257,FEBE3D4CFEBEFEBE3D4CFEBE",
  })
  void testFromWireFails(long serial, int scheme, int hash, String digest) {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ZoneMDRecord(
                Name.root, DClass.IN, 3600, serial, scheme, hash, base16.fromString(digest)));
  }

  @ParameterizedTest
  @CsvSource({
    "2147483648,0,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,0,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE",
    "2147483648,0,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C",
    "2147483648,1,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,1,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE",
    "2147483648,1,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C",
  })
  void testToAndFromWire(long serial, int scheme, int hash, String digestHex) throws IOException {
    byte[] digest = base16.fromString(digestHex);
    ZoneMDRecord md = new ZoneMDRecord(Name.root, DClass.IN, 3600, serial, scheme, hash, digest);
    byte[] data = md.toWire(Section.ANSWER);
    Record parsed = Record.fromWire(data, Section.ANSWER);
    assertInstanceOf(ZoneMDRecord.class, parsed);
    ZoneMDRecord parsedMd = (ZoneMDRecord) parsed;
    assertEquals(serial, parsedMd.getSerial());
    assertEquals(scheme, parsedMd.getScheme());
    assertEquals(hash, parsedMd.getHashAlgorithm());
    assertArrayEquals(digest, parsedMd.getDigest());
  }

  @ParameterizedTest
  @CsvSource({
    // Name ("."), ZoneMD = 63, DClass = 1, ttl=3600, length
    "00_003F_0001_00000E10_0002_8000",
    "00_003F_0001_00000E10_0004_80000000",
    "00_003F_0001_00000E10_0006_80000000_00",
    "00_003F_0001_00000E10_0008_80000000_00_00",
    "00_003F_0001_00000E10_0011_80000000_00_00_FEBE3D4CFEBEFEBE3D4CFE",
    "00_003F_0001_00000E10_0035_80000000_00_01_FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057B",
    "00_003F_0001_00000E10_0037_80000000_00_01_FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFF",
    "00_003F_0001_00000E10_0045_80000000_00_02_FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D",
    "00_003F_0001_00000E10_0047_80000000_00_02_FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C5D",
  })
  void testFromWireFails(String hex) {
    byte[] data = base16.fromString(hex.replaceAll("_", ""));
    assertThrows(WireParseException.class, () -> Record.fromWire(data, Section.ANSWER));
  }

  @ParameterizedTest
  @CsvSource({
    "2023110500,1,241,1AADC4FDD0FDB404C4848A9D7C1F1C674C31ADDFDF747454BAE966048EAE0806158EBA5569EEC4638E7A765A72F5019D",
    "2147483648,0,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,0,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE",
    "2147483648,0,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C",
    "2147483648,1,0,FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648,1,1,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEE",
    "2147483648,1,2,FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C",
  })
  void testToAndFromRData(long serial, int scheme, int hash, String digestHex) throws IOException {
    byte[] digest = base16.fromString(digestHex);
    ZoneMDRecord md = new ZoneMDRecord(Name.root, DClass.IN, 3600, serial, scheme, hash, digest);
    String data = md.rrToString();
    assertEquals(serial + " " + scheme + " " + hash + " " + digestHex, data);

    Record parsed = Record.fromString(Name.root, Type.ZONEMD, DClass.IN, 3600, data, Name.root);
    assertInstanceOf(ZoneMDRecord.class, parsed);
    ZoneMDRecord parsedMd = (ZoneMDRecord) parsed;
    assertEquals(serial, parsedMd.getSerial());
    assertEquals(scheme, parsedMd.getScheme());
    assertEquals(hash, parsedMd.getHashAlgorithm());
    assertArrayEquals(digest, parsedMd.getDigest());
  }

  @Test
  void testToWrappedRdata() throws IOException {
    String rdataIn =
        "2147483648 0 2 FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C";
    ZoneMDRecord md =
        (ZoneMDRecord)
            Record.fromString(Name.root, Type.ZONEMD, DClass.IN, 3600, rdataIn, Name.root);
    try {
      Options.set("multiline");
      String rdataOut = md.rrToString();
      String[] lines = rdataOut.split("\n");
      assertEquals(3, rdataOut.split("\n").length, "Expected lines");
      assertTrue(lines[0].contains("("), "Missing opening parenthesis");
      assertTrue(lines[1].contains("\t"), "Missing tabs");
      assertTrue(rdataOut.endsWith(")"), "Missing closing parenthesis at end of string");
    } finally {
      Options.unset("multiline");
    }
  }

  @ParameterizedTest
  @CsvSource({
    "-1 0 0 FEBE3D4CFEBEFEBE3D4CFEBE",
    "4294967296 0 0 FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648, 1 0 FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648 257 0 FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648, , 1 FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648 0 257 FEBE3D4CFEBEFEBE3D4CFEBE",
    "2147483648 0 0 FEBE3D4CFEBEFEBE3D4CFE",
    "2147483648 0 1 FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057B",
    "2147483648 0 1 FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFF",
    "2147483648 0 2 FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D",
    "2147483648 0 2 FEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4CFEBE3D4CE2EC2FFA4BA99D46CD69D6D29711E55217057BEEFEBE3D4CFEBE3D4C5D",
  })
  void testFromRDataFails(String rdata) {
    assertThrows(
        TextParseException.class,
        () -> Record.fromString(Name.root, Type.ZONEMD, DClass.IN, 3600, rdata, Name.root));
  }
}

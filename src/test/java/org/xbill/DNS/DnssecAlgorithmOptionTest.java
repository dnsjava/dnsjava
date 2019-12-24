package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.EDNSOption.Code;

public class DnssecAlgorithmOptionTest {
  @Test
  void ctor() {
    new DnssecAlgorithmOption(Code.DAU);
    new DnssecAlgorithmOption(Code.DHU);
    new DnssecAlgorithmOption(Code.N3U);

    assertThrows(IllegalArgumentException.class, () -> new DnssecAlgorithmOption(4));
    assertThrows(IllegalArgumentException.class, () -> new DnssecAlgorithmOption(8));
  }

  @Test
  void ctorOptionsEmpty() {
    DnssecAlgorithmOption o = new DnssecAlgorithmOption(Code.DAU);
    assertTrue(o.getAlgorithms().isEmpty());
  }

  @Test
  void ctorOptionsList() {
    DnssecAlgorithmOption o =
        new DnssecAlgorithmOption(Code.DAU, Collections.singletonList(Algorithm.RSASHA1));
    assertEquals(1, o.getAlgorithms().size());
  }

  @Test
  void ctorOptionsVarargs() {
    DnssecAlgorithmOption o = new DnssecAlgorithmOption(Code.DAU, Algorithm.RSASHA1);
    assertEquals(1, o.getAlgorithms().size());
  }

  @Test
  void ctorOptionsVarargsNull() {
    DnssecAlgorithmOption o = new DnssecAlgorithmOption(Code.DAU, (int[]) null);
    assertTrue(o.getAlgorithms().isEmpty());
  }

  @Test
  void parse() throws IOException {
    DNSInput in = new DNSInput(new byte[] {0, 5, 0, 2, 5, 6});
    DnssecAlgorithmOption o = (DnssecAlgorithmOption) EDNSOption.fromWire(in);
    assertEquals(Algorithm.RSASHA1, o.getAlgorithms().get(0));
    assertEquals(Algorithm.DSA_NSEC3_SHA1, o.getAlgorithms().get(1));
  }

  @Test
  void write() {
    DnssecAlgorithmOption o =
        new DnssecAlgorithmOption(Code.DAU, Algorithm.RSASHA1, Algorithm.DSA_NSEC3_SHA1);
    DNSOutput out = new DNSOutput();
    o.toWire(out);
    assertArrayEquals(new byte[] {0, 5, 0, 2, 5, 6}, out.toByteArray());
  }

  @Test
  void testToString() {
    DnssecAlgorithmOption o =
        new DnssecAlgorithmOption(Code.DAU, Algorithm.RSASHA1, Algorithm.DSA_NSEC3_SHA1);
    assertEquals("DAU: [RSASHA1, DSA-NSEC3-SHA1]", o.optionToString());
  }
}

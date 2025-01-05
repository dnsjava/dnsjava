// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class LOCRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    LOCRecord loc = new LOCRecord();
    assertEquals(0.0, loc.getVPrecision());
    assertEquals(0.0, loc.getHPrecision());
    assertEquals(-100000.0, loc.getAltitude());
    assertEquals(-596.52323, loc.getLongitude(), 0.1);
    assertEquals(-596.52323, loc.getLatitude(), 0.1);
    assertEquals(0.0, loc.getSize());
  }

  @Test
  void ctor_9arg() {
    LOCRecord loc = new LOCRecord(n, DClass.IN, 0, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5);
    assertEquals(6.5, loc.getVPrecision());
    assertEquals(5.5, loc.getHPrecision());
    assertEquals(3.5, loc.getAltitude());
    assertEquals(2.5, loc.getLongitude());
    assertEquals(1.5, loc.getLatitude());
    assertEquals(4.5, loc.getSize());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m");
    LOCRecord loc = new LOCRecord();
    loc.rdataFromString(t, null);
    assertEquals(10.0, loc.getVPrecision());
    assertEquals(10000.0, loc.getHPrecision());
    assertEquals(-2.0, loc.getAltitude());
    assertEquals(4.892, loc.getLongitude(), 0.1);
    assertEquals(52.373, loc.getLatitude(), 0.1);
    assertEquals(0.0, loc.getSize());
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class NAPTRRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t =
        new Tokenizer("100  50  \"s\"    \"http+N2L+N2C+N2R\"  \"!a\\\\!!b!i\"   www.example.com.");
    NAPTRRecord naptr = new NAPTRRecord();
    naptr.rdataFromString(t, null);
    assertEquals(100, naptr.getOrder());
    assertEquals(50, naptr.getPreference());
    assertEquals("s", naptr.getFlags());
    assertEquals("http+N2L+N2C+N2R", naptr.getService());
    assertEquals("http+N2L+N2C+N2R", naptr.getService(false));
    assertArrayEquals(
        "http+N2L+N2C+N2R".getBytes(StandardCharsets.UTF_8), naptr.getServiceAsByteArray());
    assertEquals("!a\\\\!!b!i", naptr.getRegexp());
    assertEquals("!a\\!!b!i", naptr.getRegexp(false));
    assertArrayEquals("!a\\!!b!i".getBytes(StandardCharsets.UTF_8), naptr.getRegexpAsByteArray());
    assertEquals(Name.fromConstantString("www.example.com."), naptr.getReplacement());
  }
}

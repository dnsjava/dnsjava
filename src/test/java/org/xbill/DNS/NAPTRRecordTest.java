// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class NAPTRRecordTest {

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("100  50  \"s\"    \"http+N2L+N2C+N2R\"  \"\"   www.example.com.");
    NAPTRRecord naptr = new NAPTRRecord();
    naptr.rdataFromString(t, null);
    assertEquals(100, naptr.getOrder());
    assertEquals(50, naptr.getPreference());
    assertEquals("s", naptr.getFlags());
    assertEquals("http+N2L+N2C+N2R", naptr.getService());
    assertEquals("", naptr.getRegexp());
    assertEquals(Name.fromConstantString("www.example.com."), naptr.getReplacement());
  }
}

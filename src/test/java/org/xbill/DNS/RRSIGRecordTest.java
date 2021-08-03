// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;
import org.junit.jupiter.api.Test;

class RRSIGRecordTest {

  @Test
  void rdataFromString() throws IOException, ParseException {
    Tokenizer t =
        new Tokenizer(
            "NSEC3 10 3 180 20161207204758 20161107195347 31055 example.com. GLqlvFaWiemLree+4WQeR+0ANSEYeuLW/KEWZw9mZPUJ1bcb1OQCxp43 7DNdPCSmS/RqJGiVGtSW8xsGoRgUwOdczL8s4j/z3pVi8wDlhw2jXE0k fGBiOshH+3VjZV4eLlDmDixZ3WmA9gzf0G+qAwRP9tjps2+vqRfXOpoj /UffmcMgZODEDGonHAOX/k35sBL+zIP4k6i6Kq/lpPZd8oxsxCwyxAYl E1oMxeE14TnRZoqCZdAEgvrViF91z/tnMbYAY/JNWYK4iREOuuWTLOox C0hKBsymi3fyLjwZ1NV1Bh3lqYN0rr1uo8ZSZmGrfLdg4l+hO4Xl6kG6 JTn27Q==");
    RRSIGRecord record = new RRSIGRecord();
    record.rdataFromString(t, null);
    assertEquals(10, record.getAlgorithm());
    assertEquals(31055, record.getFootprint());
    assertEquals(Name.fromConstantString("example.com."), record.getSigner());
    assertEquals(50, record.getTypeCovered());
    SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddhhmmss", Locale.US);
    formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
    assertEquals(formatter.parse("20161207204758").toInstant(), record.getExpire());
    assertEquals(formatter.parse("20161107195347").toInstant(), record.getTimeSigned());
  }
}

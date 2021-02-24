// SPDX-License-Identifier: BSD-2-Clause
// -*- Java -*-
//
// Copyright (c) 2005, Matthew J. Rutherford <rutherfo@cs.colorado.edu>
// Copyright (c) 2005, University of Colorado at Boulder
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of the University of Colorado at Boulder nor the
//   names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written
//   permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import org.junit.jupiter.api.Test;

class FormattedTimeTest {
  @Test
  void format() {
    GregorianCalendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    cal.set(2005, Calendar.MARCH, 19, 4, 4, 5);
    String out = FormattedTime.format(cal.toInstant());
    assertEquals("20050319040405", out);
  }

  @Test
  void parse() throws DateTimeParseException {
    // have to make sure to clear out the milliseconds since there
    // is occasionally a difference between when cal and cal2 are
    // instantiated.
    GregorianCalendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    cal.set(2005, Calendar.MARCH, 19, 4, 4, 5);
    cal.set(Calendar.MILLISECOND, 0);

    Instant out = FormattedTime.parse("20050319040405");
    GregorianCalendar cal2 = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    cal2.setTimeInMillis(out.toEpochMilli());
    cal2.set(Calendar.MILLISECOND, 0);
    assertEquals(cal, cal2);
  }

  @Test()
  void parseEpoch() throws DateTimeParseException {
    // have to make sure to clear out the milliseconds since there
    // is occasionally a difference between when cal and cal2 are
    // instantiated.
    GregorianCalendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    cal.set(2005, Calendar.MARCH, 19, 4, 4, 5);
    cal.set(Calendar.MILLISECOND, 0);

    Instant out = FormattedTime.parse("1111205045");
    GregorianCalendar cal2 = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
    cal2.setTimeInMillis(out.toEpochMilli());
    cal2.set(Calendar.MILLISECOND, 0);
    assertEquals(cal, cal2);
  }

  @Test
  void parse_invalid() {
    assertThrows(DateTimeParseException.class, () -> FormattedTime.parse("2004010101010"));
    assertThrows(DateTimeParseException.class, () -> FormattedTime.parse("200401010101010"));
    assertThrows(DateTimeParseException.class, () -> FormattedTime.parse("2004010101010A"));
  }
}

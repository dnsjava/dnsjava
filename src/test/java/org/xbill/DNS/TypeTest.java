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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class TypeTest {
  @Test
  void string() {
    // a regular one
    assertEquals("CNAME", Type.string(Type.CNAME));

    // one that doesn't exist
    assertTrue(Type.string(65535).startsWith("TYPE"));

    assertThrows(IllegalArgumentException.class, () -> Type.string(-1));
  }

  @Test
  void value() {
    // regular one
    assertEquals(Type.MAILB, Type.value("MAILB"));

    // one thats undefined but within range
    assertEquals(300, Type.value("TYPE300"));

    // something that unknown
    assertEquals(-1, Type.value("THIS IS DEFINITELY UNKNOWN"));

    // empty string
    assertEquals(-1, Type.value(""));
  }

  @Test
  void value_2arg() {
    assertEquals(301, Type.value("301", true));
  }

  @Test
  void isRR() {
    assertTrue(Type.isRR(Type.CNAME));
    assertFalse(Type.isRR(Type.IXFR));
  }

  private static final int MYTXT = 65534;
  private static final String MYTXTName = "MYTXT";

  private static class MYTXTRecord extends TXTBase {
    MYTXTRecord() {}

    public MYTXTRecord(Name name, int dclass, long ttl, List<String> strings) {
      super(name, MYTXT, dclass, ttl, strings);
    }

    public MYTXTRecord(Name name, int dclass, long ttl, String string) {
      super(name, MYTXT, dclass, ttl, string);
    }
  }

  private static class TXTRecordReplacement extends TXTBase {
    TXTRecordReplacement() {}

    public TXTRecordReplacement(Name name, int dclass, long ttl, List<String> strings) {
      super(name, Type.TXT, dclass, ttl, strings);
    }

    public TXTRecordReplacement(Name name, int dclass, long ttl, String string) {
      super(name, Type.TXT, dclass, ttl, string);
    }
  }

  @Test
  void checkCustomRecords() throws Exception {
    // test "private use" record

    Type.register(MYTXT, MYTXTName, MYTXTRecord::new);
    Name testOwner = Name.fromConstantString("example.");
    MYTXTRecord testRecord = new MYTXTRecord(testOwner, DClass.IN, 3600, "hello world");

    byte[] wireData = testRecord.toWire(Section.ANSWER);
    Record record = Record.fromWire(new DNSInput(wireData), Section.ANSWER, false);
    assertEquals(MYTXTRecord.class, record.getClass());
    assertEquals(MYTXT, record.getType());

    byte[] textData = testRecord.toString().getBytes(StandardCharsets.US_ASCII);
    Master m = new Master(new ByteArrayInputStream(textData));
    record = m.nextRecord();
    assertNotNull(record);
    assertEquals(MYTXTRecord.class, record.getClass());
    assertEquals(MYTXT, record.getType());
    m.close();

    Type.register(MYTXT, MYTXTName, null);
    record = Record.fromWire(new DNSInput(wireData), Section.ANSWER, false);
    assertEquals(UNKRecord.class, record.getClass());
    assertEquals(MYTXT, record.getType());

    // test implementation replacement

    try {
      assertThrows(
          IllegalArgumentException.class,
          () -> Type.register(Type.TXT, "SOA", TXTRecordReplacement::new));

      Type.register(Type.TXT, "TXT", TXTRecordReplacement::new);
      TXTRecord testRecord2 = new TXTRecord(testOwner, DClass.IN, 3600, "howdy");
      wireData = testRecord2.toWire(Section.ANSWER);
      record = Record.fromWire(new DNSInput(wireData), Section.ANSWER, false);
      assertEquals(TXTRecordReplacement.class, record.getClass());
      assertEquals(Type.TXT, record.getType());

      byte[] textData2 = testRecord2.toString().getBytes(StandardCharsets.US_ASCII);
      m = new Master(new ByteArrayInputStream(textData2));
      record = m.nextRecord();
      assertNotNull(record);
      assertEquals(TXTRecordReplacement.class, record.getClass());
      assertEquals(Type.TXT, record.getType());
      m.close();

    } finally {
      // restore default implementation as needed by other tests
      Type.register(Type.TXT, "TXT", TXTRecord::new);
    }
  }
}

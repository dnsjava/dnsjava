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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.junit.jupiter.api.Test;

public class MessageTest {
  static class Test_init {
    @Test
    void ctor_0arg() {
      Message m = new Message();
      assertTrue(m.getSection(0).isEmpty());
      assertTrue(m.getSection(1).isEmpty());
      assertTrue(m.getSection(3).isEmpty());
      assertTrue(m.getSection(2).isEmpty());
      assertThrows(IndexOutOfBoundsException.class, () -> m.getSection(4));
      Header h = m.getHeader();
      assertEquals(0, h.getCount(0));
      assertEquals(0, h.getCount(1));
      assertEquals(0, h.getCount(2));
      assertEquals(0, h.getCount(3));
    }

    @Test
    void ctor_1arg() {
      Message m = new Message(10);
      assertEquals(new Header(10).toString(), m.getHeader().toString());
      assertTrue(m.getSection(0).isEmpty());
      assertTrue(m.getSection(1).isEmpty());
      assertTrue(m.getSection(2).isEmpty());
      assertTrue(m.getSection(3).isEmpty());
      assertThrows(IndexOutOfBoundsException.class, () -> m.getSection(4));
      Header h = m.getHeader();
      assertEquals(0, h.getCount(0));
      assertEquals(0, h.getCount(1));
      assertEquals(0, h.getCount(2));
      assertEquals(0, h.getCount(3));
    }

    @Test
    void newQuery() throws TextParseException, UnknownHostException {
      Name n = Name.fromString("The.Name.");
      ARecord ar = new ARecord(n, DClass.IN, 1, InetAddress.getByName("192.168.101.110"));

      Message m = Message.newQuery(ar);
      assertEquals(1, m.getSection(0).size());
      assertEquals(ar, m.getSection(0).get(0));
      assertTrue(m.getSection(1).isEmpty());
      assertTrue(m.getSection(2).isEmpty());
      assertTrue(m.getSection(3).isEmpty());

      Header h = m.getHeader();
      assertEquals(1, h.getCount(0));
      assertEquals(0, h.getCount(1));
      assertEquals(0, h.getCount(2));
      assertEquals(0, h.getCount(3));
      assertEquals(Opcode.QUERY, h.getOpcode());
      assertTrue(h.getFlag(Flags.RD));
    }

    @Test
    void sectionToWire() throws IOException {
      Message m = new Message(4711);
      Name n2 = Name.fromConstantString("test2.example.");
      m.addRecord(new TXTRecord(n2, DClass.IN, 86400, "other record"), Section.ADDITIONAL);
      Name n = Name.fromConstantString("test.example.");
      m.addRecord(new TXTRecord(n, DClass.IN, 86400, "example text -1-"), Section.ADDITIONAL);
      m.addRecord(new TXTRecord(n, DClass.IN, 86400, "example text -2-"), Section.ADDITIONAL);
      m.addRecord(new TXTRecord(n, DClass.IN, 86400, "example text -3-"), Section.ADDITIONAL);
      m.addRecord(new TXTRecord(n, DClass.IN, 86400, "example text -4-"), Section.ADDITIONAL);
      m.addRecord(new OPTRecord(512, 0, 0, 0), Section.ADDITIONAL);

      for (int i = 5; i < 50; i++) {
        m.addRecord(
            new TXTRecord(n, DClass.IN, 86400, "example text -" + i + "-"), Section.ADDITIONAL);
      }

      byte[] binary = m.toWire(512);
      Message m2 = new Message(binary);
      assertEquals(2, m2.getHeader().getCount(Section.ADDITIONAL));
      List<Record> records = m2.getSection(Section.ADDITIONAL);
      assertEquals(2, records.size());
      assertEquals(TXTRecord.class, records.get(0).getClass());
      assertEquals(OPTRecord.class, records.get(1).getClass());
    }
  }
}

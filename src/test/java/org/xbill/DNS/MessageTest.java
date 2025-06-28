// SPDX-License-Identifier: BSD-3-Clause
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.utils.base64;

class MessageTest {
  @Test
  void ctor_0arg() {
    Message m = new Message();
    assertTrue(m.getSection(0).isEmpty());
    assertTrue(m.getSection(1).isEmpty());
    assertTrue(m.getSection(2).isEmpty());
    assertTrue(m.getSection(3).isEmpty());
    assertThrows(IllegalArgumentException.class, () -> m.getSection(4));
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
    assertThrows(IllegalArgumentException.class, () -> m.getSection(4));
    Header h = m.getHeader();
    assertEquals(0, h.getCount(0));
    assertEquals(0, h.getCount(1));
    assertEquals(0, h.getCount(2));
    assertEquals(0, h.getCount(3));
  }

  @Test
  void ctor_byteBuffer() throws IOException {
    byte[] arr =
        base64.fromString(
            "EEuBgAABAAEABAAIA3d3dwZnb29nbGUDY29tAAABAAHADAABAAEAAAAaAASO+rokwBAAAgABAAFHCwAGA25zMcAQwBAAAgABAAFHCwAGA25zNMAQwBAAAgABAAFHCwAGA25zM8AQwBAAAgABAAFHCwAGA25zMsAQwDwAAQABAADObwAE2O8gCsByAAEAAQABrVEABNjvIgrAYAABAAEAAVqZAATY7yQKwE4AAQABAAK9RQAE2O8mCsA8ABwAAQAD4a0AECABSGBIAgAyAAAAAAAAAArAcgAcAAEAAtDgABAgAUhgSAIANAAAAAAAAAAKwGAAHAABAACSagAQIAFIYEgCADYAAAAAAAAACsBOABwAAQAErVoAECABSGBIAgA4AAAAAAAAAAo=");

    ByteBuffer wrap = ByteBuffer.allocate(arr.length + 2);

    // prepend length, like when reading a response from a TCP channel
    wrap.putShort((short) arr.length);
    wrap.put(arr);
    wrap.flip();
    wrap.getShort(); // read the prepended length

    Message m = new Message(wrap);
    assertEquals(Name.fromConstantString("www.google.com."), m.getQuestion().getName());
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

  @Test
  void testQuestionClone() {
    Name qname = Name.fromConstantString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    Message clone = query.clone();
    assertEquals(query.getHeader().getID(), clone.getHeader().getID());
    assertEquals(query.getQuestion().getName(), clone.getQuestion().getName());
  }

  @Test
  void testResponseClone() throws UnknownHostException {
    Name qname = Name.fromConstantString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message response = new Message();
    response.getHeader().setFlag(Flags.QR);
    response.addRecord(question, Section.QUESTION);
    response.addRecord(
        new ARecord(qname, DClass.IN, 0, InetAddress.getByName("127.0.0.1")), Section.ANSWER);
    Message clone = response.clone();
    assertEquals(clone.getQuestion(), response.getQuestion());
    assertEquals(clone.getSection(Section.ANSWER), response.getSection(Section.ANSWER));
  }

  @Test
  void normalize() throws WireParseException {
    Record queryRecord =
        Record.newRecord(Name.fromConstantString("example.com."), Type.MX, DClass.IN);
    Message query = Message.newQuery(queryRecord);
    Message response = new Message();
    response.addRecord(queryRecord, Section.QUESTION);
    response.addRecord(queryRecord, Section.ADDITIONAL);
    response = response.normalize(query, true);
    assertThat(response.getSection(Section.ANSWER)).isEmpty();
    assertThat(response.getHeader().getCount(Section.ANSWER)).isZero();
    assertThat(response.getSection(Section.ADDITIONAL)).isEmpty();
    assertThat(response.getHeader().getCount(Section.ADDITIONAL)).isZero();
  }
}

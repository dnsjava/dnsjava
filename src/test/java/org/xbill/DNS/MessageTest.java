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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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
    assertThat(m.getSection(0)).isEmpty();
    assertThat(m.getSection(1)).isEmpty();
    assertThat(m.getSection(2)).isEmpty();
    assertThat(m.getSection(3)).isEmpty();
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m.getSection(4));
    Header h = m.getHeader();
    assertThat(h.getCount(0)).isZero();
    assertThat(h.getCount(1)).isZero();
    assertThat(h.getCount(2)).isZero();
    assertThat(h.getCount(3)).isZero();
  }

  @Test
  void ctor_1arg() {
    Message m = new Message(10);
    assertThat(m.getHeader()).hasToString(new Header(10).toString());
    assertThat(m.getSection(0)).isEmpty();
    assertThat(m.getSection(1)).isEmpty();
    assertThat(m.getSection(2)).isEmpty();
    assertThat(m.getSection(3)).isEmpty();
    assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> m.getSection(4));
    Header h = m.getHeader();
    assertThat(h.getCount(0)).isZero();
    assertThat(h.getCount(1)).isZero();
    assertThat(h.getCount(2)).isZero();
    assertThat(h.getCount(3)).isZero();
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
    assertThat(m.getQuestion().getName()).isEqualTo(Name.fromConstantString("www.google.com."));
  }

  @Test
  void newQuery() throws TextParseException, UnknownHostException {
    Name n = Name.fromString("The.Name.");
    ARecord ar = new ARecord(n, DClass.IN, 1, InetAddress.getByName("192.168.101.110"));

    Message m = Message.newQuery(ar);
    assertThat(m.getSection(0)).hasSize(1);
    assertThat(m.getSection(0).get(0)).isEqualTo(ar);
    assertThat(m.getSection(1)).isEmpty();
    assertThat(m.getSection(2)).isEmpty();
    assertThat(m.getSection(3)).isEmpty();

    Header h = m.getHeader();
    assertThat(h.getCount(0)).isOne();
    assertThat(h.getCount(1)).isZero();
    assertThat(h.getCount(2)).isZero();
    assertThat(h.getCount(3)).isZero();
    assertThat(h.getOpcode()).isEqualTo(Opcode.QUERY);
    assertThat(h.getFlag(Flags.RD)).isTrue();
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
    assertThat(m2.getHeader().getCount(Section.ADDITIONAL)).isEqualTo(2);
    List<Record> records = m2.getSection(Section.ADDITIONAL);
    assertThat(records).hasSize(2);
    assertThat(records.get(0).getClass()).isEqualTo(TXTRecord.class);
    assertThat(records.get(1).getClass()).isEqualTo(OPTRecord.class);
  }

  @Test
  void testQuestionClone() {
    Name qname = Name.fromConstantString("www.example.");
    Record question = Record.newRecord(qname, Type.A, DClass.IN);
    Message query = Message.newQuery(question);
    Message clone = query.clone();
    assertThat(clone.getHeader().getID()).isEqualTo(query.getHeader().getID());
    assertThat(clone.getQuestion().getName()).isEqualTo(query.getQuestion().getName());
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
    assertThat(response.getQuestion()).isEqualTo(clone.getQuestion());
    assertThat(response.getSection(Section.ANSWER)).isEqualTo(clone.getSection(Section.ANSWER));
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

  @Test
  void normalizeCnames() throws WireParseException {
    Name exampleCom = Name.fromConstantString("example.com.");
    Record queryRecord = Record.newRecord(exampleCom, Type.MX, DClass.IN);
    Message query = Message.newQuery(queryRecord);
    Message response = new Message();
    response.addRecord(queryRecord, Section.QUESTION);
    response.addRecord(
        new CNAMERecord(
            Name.fromConstantString("example.com."),
            DClass.IN,
            3600,
            Name.fromConstantString("1.example.com.")),
        Section.ANSWER);
    response.addRecord(
        new CNAMERecord(
            Name.fromConstantString("1.example.com."),
            DClass.IN,
            3600,
            Name.fromConstantString("2.example.com.")),
        Section.ANSWER);
    response.addRecord(
        new CNAMERecord(
            Name.fromConstantString("2.example.com."),
            DClass.IN,
            3600,
            Name.fromConstantString("3.example.com.")),
        Section.ANSWER);
    response.addRecord(
        new CNAMERecord(
            Name.fromConstantString("3.example.com."),
            DClass.IN,
            3600,
            Name.fromConstantString("4.example.com.")),
        Section.ANSWER);
    response.addRecord(
        new CNAMERecord(
            Name.fromConstantString("4.example.com."),
            DClass.IN,
            3600,
            Name.fromConstantString("5.example.com.")),
        Section.ANSWER);
    response.addRecord(
        new CNAMERecord(
            Name.fromConstantString("4.example.com."),
            DClass.IN,
            3600,
            Name.fromConstantString("6.example.com.")),
        Section.ANSWER);
    List<Record> expectedRecords = response.getSection(Section.ANSWER).subList(0, 5);
    response = response.normalize(query, false);
    assertThat(response.getSection(Section.ANSWER)).containsExactlyElementsOf(expectedRecords);
  }

  @Test
  void truncate() {
    Message m = new Message();
    m.addRecord(new OPTRecord(768, 0, 0), Section.ADDITIONAL);
    assertThatThrownBy(() -> m.toWire(12))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Message needs at least");
  }

  @Test
  void truncationSkipsCompressedName1() throws IOException {
    Name exampleCom = Name.fromConstantString("example.com.");
    Name testExampleCom = Name.fromConstantString("test.example.com.");
    Message m = new Message();
    m.addRecord(new ARecord(exampleCom, DClass.IN, 3600, new byte[4]), Section.ANSWER);
    int maxLength = m.toWire().length + 1;
    m.addRecord(new ARecord(testExampleCom, DClass.IN, 3600, new byte[4]), Section.ANSWER);
    Compression c = new Compression();
    DNSOutput out = new DNSOutput();
    assertThat(m.toWire(out, c, maxLength)).isFalse();
    Message mParsedFromBytes = new Message(out.toByteArray());
    assertThat(mParsedFromBytes.getHeader().getFlag(Flags.TC)).isTrue();
    assertThat(c.get(testExampleCom)).isEqualTo(-1);
  }

  @Test
  void truncationSkipsCompressedName2() throws IOException {
    Name exampleCom = Name.fromConstantString("example.com.");
    Name testExampleCom = Name.fromConstantString("test.example.com.");
    TSIG tsig = new TSIG(TSIG.HMAC_SHA256, testExampleCom, new byte[16]);
    Message m = new Message();
    ARecord aExampleCom = new ARecord(exampleCom, DClass.IN, 3600, new byte[4]);
    m.addRecord(aExampleCom, Section.ANSWER);
    int maxLength = m.toWire().length;

    m.addRecord(new ARecord(testExampleCom, DClass.IN, 3600, new byte[4]), Section.ANSWER);
    m.setTSIG(tsig, Rcode.NOERROR, null);

    Compression c = new Compression();
    DNSOutput out = new DNSOutput();
    assertThat(m.toWire(out, c, maxLength + tsig.recordLength() + Header.LENGTH)).isFalse();
    Message mParsedFromBytes = new Message(out.toByteArray());
    assertThat(mParsedFromBytes.getHeader().getFlag(Flags.TC)).isTrue();
    assertThat(mParsedFromBytes.getSection(Section.ANSWER)).containsExactly(aExampleCom);
    assertThat(c.get(testExampleCom)).isPositive();
    assertDoesNotThrow(m::getTSIG);
  }

  @Test
  void toWireWithPresetTruncation() throws MessageSizeExceededException {
    Name exampleCom = Name.fromConstantString("example.com.");
    Message m = new Message(1);
    m.getHeader().setFlag(Flags.TC);
    m.addRecord(Record.newRecord(exampleCom, Type.A, DClass.IN), Section.QUESTION);
    byte[] w = m.toWire(512, false);
    assertThat(w).hasSameSizeAs(m.toWire());
  }

  @Test
  void testAddRecord() {
    Message m = new Message();
    Name n = Name.fromConstantString("example.com.");
    ARecord r = new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress());
    m.addRecord(r, Section.ANSWER);
    assertThat(m.findRecord(r, Section.ANSWER)).isTrue();
    m.removeRecord(r, Section.ANSWER);
    assertThat(m.findRecord(r, Section.ANSWER)).isFalse();
  }

  @Test
  void testRemoveAllRecords() {
    Message m = new Message();
    Name n = Name.fromConstantString("example.com.");
    ARecord r1 = new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress());
    ARecord r2 = new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress());
    m.addRecord(r1, Section.ANSWER);
    m.addRecord(r2, Section.ANSWER);
    m.removeAllRecords(Section.ANSWER);
    assertThat(m.getSection(Section.ANSWER)).isEmpty();
  }

  @Test
  void testGetOPT() {
    Message m = new Message();
    m.addRecord(new OPTRecord(512, 0, 0, 0), Section.ADDITIONAL);
    assertThat(m.getOPT()).isNotNull();
  }

  @Test
  void testToString() {
    Message m = new Message();
    m.addRecord(
        Record.newRecord(Name.fromConstantString("example.com."), Type.A, DClass.IN),
        Section.QUESTION);
    String s = m.toString();
    assertThat(s).contains("example.com.").contains("QUESTION");
  }

  @Test
  void testNewUpdate() {
    Name n = Name.fromConstantString("example.com.");
    Message m = Message.newUpdate(n);
    assertThat(m.getHeader().getOpcode()).isEqualTo(Opcode.UPDATE);
    assertThat(m.getSection(Section.ZONE).get(0).getName()).isEqualTo(n);
  }

  @Test
  void testGetSectionRRsets() {
    Message m = new Message();
    Name n = Name.fromConstantString("example.com.");
    m.addRecord(new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress()), Section.ANSWER);
    m.addRecord(new ARecord(n, DClass.IN, 3601, InetAddress.getLoopbackAddress()), Section.ANSWER);
    List<RRset> rrsets = m.getSectionRRsets(Section.ANSWER);
    // Even with different TTLs, they should be grouped if name, type, dclass match
    assertThat(rrsets).hasSize(1);
  }

  @Test
  void testFindRRset() {
    Message m = new Message();
    Name n = Name.fromConstantString("example.com.");
    m.addRecord(new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress()), Section.ANSWER);
    assertThat(m.findRRset(n, Type.A, Section.ANSWER)).isTrue();
    assertThat(m.findRRset(n, Type.A)).isTrue();
    assertThat(m.findRRset(n, Type.AAAA)).isFalse();
  }

  @Test
  void testGetSectionArray() {
    Message m = new Message();
    Name n = Name.fromConstantString("example.com.");
    m.addRecord(new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress()), Section.ANSWER);
    @SuppressWarnings("deprecation")
    Record[] records = m.getSectionArray(Section.ANSWER);
    assertThat(records.length).isOne();
    assertThat(records[0]).isInstanceOf(ARecord.class);
  }

  @Test
  void testClone() {
    Message m = new Message();
    m.getHeader().setID(1234);
    Name n = Name.fromConstantString("example.com.");
    m.addRecord(new ARecord(n, DClass.IN, 3600, InetAddress.getLoopbackAddress()), Section.ANSWER);
    Message m2 = m.clone();
    assertThat(m2.getHeader().getID()).isEqualTo(1234);
    assertThat(m2.getSection(Section.ANSWER)).hasSize(1);
  }
}

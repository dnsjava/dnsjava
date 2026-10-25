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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RecordTest {
  private static class SubRecord extends Record {
    SubRecord() {}

    SubRecord(Name name, int type, int dclass, long ttl) {
      super(name, type, dclass, ttl);
    }

    @Override
    public void rrFromWire(DNSInput in) {}

    @Override
    public String rrToString() {
      return "{SubRecord: rrToString}";
    }

    @Override
    public void rdataFromString(Tokenizer t, Name origin) {}

    @Override
    public void rrToWire(DNSOutput out, Compression c, boolean canonical) {}

    // makes it callable by test code
    public static byte[] byteArrayFromString(String in) throws TextParseException {
      return Record.byteArrayFromString(in);
    }

    // make it callable by test code
    public static String byteArrayToString(byte[] in, boolean quote) {
      return Record.byteArrayToString(in, quote);
    }

    // make it callable by test code
    public static String unknownToString(byte[] in) {
      return Record.unknownToString(in);
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
      throw new CloneNotSupportedException();
    }
  }

  @Test
  void ctor_0arg() {
    SubRecord sr = new SubRecord();
    assertThat(sr.getName()).isNull();
    assertThat(sr.getType()).isZero();
    assertThat(sr.getTTL()).isZero();
    assertThat(sr.getDClass()).isZero();
  }

  @Test
  void ctor_4arg() throws TextParseException {
    Name n = Name.fromString("my.name.");
    int t = Type.A;
    int d = DClass.IN;
    long ttl = 0xABCDEL;

    SubRecord r = new SubRecord(n, t, d, ttl);
    assertThat(r.getName()).isEqualTo(n);
    assertThat(r.getType()).isEqualTo(t);
    assertThat(r.getDClass()).isEqualTo(d);
    assertThat(r.getTTL()).isEqualTo(ttl);
  }

  @Test
  void ctor_4arg_invalid() throws TextParseException {
    Name n = Name.fromString("my.name.");
    Name r = Name.fromString("my.relative.name");
    int t = Type.A;
    int d = DClass.IN;
    long ttl = 0xABCDEL;

    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> new SubRecord(r, t, d, ttl));

    assertThatExceptionOfType(InvalidTypeException.class)
        .isThrownBy(() -> new SubRecord(n, -1, d, ttl));

    assertThatExceptionOfType(InvalidDClassException.class)
        .isThrownBy(() -> new SubRecord(n, t, -1, ttl));

    assertThatExceptionOfType(InvalidTTLException.class)
        .isThrownBy(() -> new SubRecord(n, t, d, -1));
  }

  @Test
  void newRecord_3arg() throws TextParseException {
    Name n = Name.fromString("my.name.");
    Name r = Name.fromString("my.relative.name");
    int t = Type.A;
    int d = DClass.IN;

    Record rec = Record.newRecord(n, t, d);
    assertThat(rec).isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isZero();

    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> Record.newRecord(r, t, d));
  }

  @Test
  void newRecord_4arg() throws TextParseException {
    Name n = Name.fromString("my.name.");
    Name r = Name.fromString("my.relative.name");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;

    Record rec = Record.newRecord(n, t, d, ttl);
    assertThat(rec).isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);

    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> Record.newRecord(r, t, d, ttl));
  }

  @Test
  void newRecord_5arg() throws TextParseException, UnknownHostException {
    Name n = Name.fromString("my.name.");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;
    byte[] data = {(byte) 123, (byte) 232, (byte) 0, (byte) 255};
    InetAddress exp = InetAddress.getByName("123.232.0.255");

    Record rec = Record.newRecord(n, t, d, ttl, data);
    assertThat(rec).isInstanceOf(ARecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
    assertThat(((ARecord) rec).getAddress()).isEqualTo(exp);
  }

  @Test
  void newRecord_6arg() throws TextParseException, UnknownHostException {
    Name n = Name.fromString("my.name.");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;
    byte[] data = {(byte) 123, (byte) 232, (byte) 0, (byte) 255};
    InetAddress exp = InetAddress.getByName("123.232.0.255");

    Record rec = Record.newRecord(n, t, d, ttl, 0, null);
    assertThat(rec).isNotNull().isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);

    rec = Record.newRecord(n, t, d, ttl, data.length, data);
    assertThat(rec).isNotNull().isInstanceOf(ARecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
    assertThat(((ARecord) rec).getAddress()).isEqualTo(exp);

    rec = Record.newRecord(n, Type.NIMLOC, d, ttl, data.length, data);
    assertThat(rec).isNotNull().isInstanceOf(UNKRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(Type.NIMLOC);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
    assertThat(((UNKRecord) rec).getData()).containsExactly(data);
  }

  @Test
  void newRecord_6arg_invalid() throws TextParseException {
    Name n = Name.fromString("my.name.");
    Name r = Name.fromString("my.relative.name");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;
    byte[] data = {(byte) 123, (byte) 232, (byte) 0, (byte) 255};

    assertThat(Record.newRecord(n, t, d, ttl, 0, new byte[0])).isNull();
    assertThat(Record.newRecord(n, t, d, ttl, 1, new byte[0])).isNull();
    assertThat(Record.newRecord(n, t, d, ttl, data.length + 1, data)).isNull();
    assertThat(
            Record.newRecord(n, t, d, ttl, 5, new byte[] {data[0], data[1], data[2], data[3], 0}))
        .isNull();
    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> Record.newRecord(r, t, d, ttl, 0, null));
  }

  @Test
  void fromWire() throws IOException {
    Name n = Name.fromString("my.name.");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;
    byte[] data = {(byte) 123, (byte) 232, (byte) 0, (byte) 255};
    InetAddress exp = InetAddress.getByName("123.232.0.255");

    DNSOutput out = new DNSOutput();
    n.toWire(out, null);
    out.writeU16(t);
    out.writeU16(d);
    out.writeU32(ttl);
    out.writeU16(data.length);
    out.writeByteArray(data);

    DNSInput in = new DNSInput(out.toByteArray());

    Record rec = Record.fromWire(in, Section.ANSWER, false);
    assertThat(rec).isInstanceOf(ARecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
    assertThat(((ARecord) rec).getAddress()).isEqualTo(exp);

    in = new DNSInput(out.toByteArray());
    rec = Record.fromWire(in, Section.QUESTION, false);
    assertThat(rec).isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isZero();

    in = new DNSInput(out.toByteArray());
    rec = Record.fromWire(in, Section.QUESTION);
    assertThat(rec).isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isZero();

    rec = Record.fromWire(out.toByteArray(), Section.QUESTION);
    assertThat(rec).isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isZero();

    out = new DNSOutput();
    n.toWire(out, null);
    out.writeU16(t);
    out.writeU16(d);
    out.writeU32(ttl);
    out.writeU16(0);

    in = new DNSInput(out.toByteArray());

    rec = Record.fromWire(in, Section.ANSWER, true);
    assertThat(rec).isInstanceOf(EmptyRecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
  }

  @Test
  void toWire() throws IOException {
    Name n = Name.fromString("my.name.");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;
    byte[] data = {(byte) 123, (byte) 232, (byte) 0, (byte) 255};

    // a non-QUESTION
    DNSOutput out = new DNSOutput();
    n.toWire(out, null);
    out.writeU16(t);
    out.writeU16(d);
    out.writeU32(ttl);
    out.writeU16(data.length);
    out.writeByteArray(data);

    byte[] exp = out.toByteArray();

    Record rec = Record.newRecord(n, t, d, ttl, data.length, data);

    out = new DNSOutput();

    assertThat(rec).isNotNull();
    rec.toWire(out, Section.ANSWER, null);

    byte[] after = out.toByteArray();

    assertThat(after).containsExactly(exp);

    // an equivalent call
    after = rec.toWire(Section.ANSWER);
    assertThat(after).containsExactly(exp);

    // a QUESTION entry
    out = new DNSOutput();
    n.toWire(out, null);
    out.writeU16(t);
    out.writeU16(d);

    exp = out.toByteArray();
    out = new DNSOutput();
    rec.toWire(out, Section.QUESTION, null);
    after = out.toByteArray();

    assertThat(after).containsExactly(exp);
  }

  @Test
  void toWireCanonical() throws IOException {
    Name n = Name.fromString("My.Name.");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xDBE8;
    byte[] data = {(byte) 123, (byte) 232, (byte) 0, (byte) 255};

    DNSOutput out = new DNSOutput();
    n.toWireCanonical(out);
    out.writeU16(t);
    out.writeU16(d);
    out.writeU32(ttl);
    out.writeU16(data.length);
    out.writeByteArray(data);

    byte[] exp = out.toByteArray();

    Record rec = Record.newRecord(n, t, d, ttl, data.length, data);

    assertThat(rec).isNotNull();
    byte[] after = rec.toWireCanonical();
    assertThat(after).containsExactly(exp);
  }

  @Test
  void rdataToWireCanonical() throws IOException {
    Name n = Name.fromString("My.Name.");
    Name n2 = Name.fromString("My.Second.Name.");
    int t = Type.NS;
    int d = DClass.IN;
    int ttl = 0xABE99;
    DNSOutput out = new DNSOutput();
    n2.toWire(out, null);
    byte[] data = out.toByteArray();

    out = new DNSOutput();
    n2.toWireCanonical(out);
    byte[] exp = out.toByteArray();

    Record rec = Record.newRecord(n, t, d, ttl, data.length, data);
    assertThat(rec).isNotNull().isInstanceOf(NSRecord.class);

    byte[] after = rec.rdataToWireCanonical();

    assertThat(after).containsExactly(exp);
  }

  @Test
  void rdataToString() throws IOException {
    Name n = Name.fromString("My.Name.");
    Name n2 = Name.fromString("My.Second.Name.");
    int t = Type.NS;
    int d = DClass.IN;
    int ttl = 0xABE99;
    DNSOutput out = new DNSOutput();
    n2.toWire(out, null);
    byte[] data = out.toByteArray();

    Record rec = Record.newRecord(n, t, d, ttl, data.length, data);
    assertThat(rec).isNotNull().isInstanceOf(NSRecord.class);
    assertThat(rec.rdataToString()).isEqualTo(rec.rrToString());
  }

  @Test
  void test_toString() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name n2 = Name.fromString("My.Second.Name.");
    int t = Type.NS;
    int d = DClass.IN;
    int ttl = 0xABE99;
    DNSOutput o = new DNSOutput();
    n2.toWire(o, null);
    byte[] data = o.toByteArray();

    Record rec = Record.newRecord(n, t, d, ttl, data.length, data);
    assertThat(rec).isNotNull();
    String out = rec.toString();

    assertThat(out)
        .contains(n.toString())
        .contains(n2.toString())
        .contains("NS")
        .contains("IN")
        .contains(ttl + "");

    try {
      Options.set("BINDTTL");

      out = rec.toString();
      assertThat(out)
          .contains(n.toString())
          .contains(n2.toString())
          .contains("NS")
          .contains("IN")
          .contains(TTL.format(ttl));

      Options.set("noPrintIN");
      out = rec.toString();
      assertThat(out)
          .contains(n.toString())
          .contains(n2.toString())
          .contains("NS")
          .doesNotContain("IN")
          .contains(TTL.format(ttl));
    } finally {
      Options.unset("BINDTTL");
      Options.unset("noPrintIN");
    }
  }

  @Test
  void byteArrayFromString() throws TextParseException {
    String in = "the 98 \" ' quick 0xAB brown";
    byte[] out = SubRecord.byteArrayFromString(in);
    assertThat(out).containsExactly(in.getBytes());

    in = " \\031Aa\\;\\\"\\\\~\\127\\255";
    byte[] exp = {' ', 0x1F, 'A', 'a', ';', '"', '\\', 0x7E, 0x7F, (byte) 0xFF};
    out = SubRecord.byteArrayFromString(in);
    assertThat(out).containsExactly(exp);
  }

  @Test
  void byteArrayFromString_invalid() {
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < 257; ++i) {
      b.append('A');
    }
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> SubRecord.byteArrayFromString(b.toString()));

    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> SubRecord.byteArrayFromString("\\256"));
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> SubRecord.byteArrayFromString("\\25a"));
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> SubRecord.byteArrayFromString("\\25"));

    b.append("\\233");
    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> SubRecord.byteArrayFromString(b.toString()));
  }

  @Test
  void byteArrayToString() {
    byte[] in = {' ', 0x1F, 'A', 'a', ';', '"', '\\', 0x7E, 0x7F, (byte) 0xFF};
    String exp = "\" \\031Aa;\\\"\\\\~\\127\\255\"";
    assertThat(SubRecord.byteArrayToString(in, true)).isEqualTo(exp);
  }

  @Test
  void unknownToString() {
    byte[] data = {
      (byte) 0x12,
      (byte) 0x34,
      (byte) 0x56,
      (byte) 0x78,
      (byte) 0x9A,
      (byte) 0xBC,
      (byte) 0xDE,
      (byte) 0xFF
    };
    String out = SubRecord.unknownToString(data);

    assertThat(out).contains("" + data.length).contains("123456789ABCDEFF");
  }

  @Test
  void fromString() throws IOException {
    Name n = Name.fromString("My.N.");
    Name n2 = Name.fromString("My.Second.Name.");
    int t = Type.A;
    int d = DClass.IN;
    int ttl = 0xABE99;
    String sa = "191.234.43.10";
    InetAddress addr = InetAddress.getByName(sa);
    byte[] b = {(byte) 191, (byte) 234, (byte) 43, (byte) 10};

    Tokenizer st = new Tokenizer(sa);
    Record rec = Record.fromString(n, t, d, ttl, st, n2);
    assertThat(rec).isInstanceOf(ARecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
    assertThat(((ARecord) rec).getAddress()).isEqualTo(addr);

    String unkData = SubRecord.unknownToString(b);
    st = new Tokenizer(unkData);
    rec = Record.fromString(n, t, d, ttl, st, n2);
    assertThat(rec).isInstanceOf(ARecord.class);
    assertThat(rec.getName()).isEqualTo(n);
    assertThat(rec.getType()).isEqualTo(t);
    assertThat(rec.getDClass()).isEqualTo(d);
    assertThat(rec.getTTL()).isEqualTo(ttl);
    assertThat(((ARecord) rec).getAddress()).isEqualTo(addr);
  }

  @Test
  void fromString_empty() throws IOException {
    Name n = Name.fromString("My.N.");
    Record r = Record.fromString(n, 0, DClass.IN, 3600, "\\# 0", Name.root);
    assertThat(r).isInstanceOf(UNKRecord.class);
    assertThat(((UNKRecord) r).getData()).isEmpty();
  }

  @Test
  void fromString_relative() throws IOException {
    Name rel = Name.fromString("My.R");
    Name n2 = Name.fromString("My.Second.Name.");

    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> Record.fromString(rel, Type.A, DClass.IN, 3600, "191.234.43.10", n2));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "191.234.43.10 another_token",
        "\\# 100 ABCDE",
        "\\# 100",
      })
  void fromString_invalid(String data) throws IOException {
    Name n = Name.fromString("My.N.");
    Name n2 = Name.fromString("My.Second.Name.");

    assertThatExceptionOfType(TextParseException.class)
        .isThrownBy(() -> Record.fromString(n, Type.A, DClass.IN, 3600, data, n2));
  }

  @Test
  void getRRsetType() throws TextParseException {
    Name n = Name.fromString("My.N.");

    Record r = Record.newRecord(n, Type.A, DClass.IN, 0);
    assertThat(r.getRRsetType()).isEqualTo(Type.A);

    Instant now = Instant.now();
    r = new RRSIGRecord(n, DClass.IN, 0, Type.A, 1, 0, now, now, 10, n, new byte[0]);
    assertThat(r.getRRsetType()).isEqualTo(Type.A);

    // create an "EmptyRecord" instance with RRSIG type. As it has no RDATA,
    // it cannot return the covered type
    r = Record.newRecord(n, Type.RRSIG, DClass.IN, 86400, 0, null);
    assertThat(r).isNotNull();
    assertThat(r.getRRsetType()).isEqualTo(Type.RRSIG);
  }

  @Test
  void sameRRset() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name m = Name.fromString("My.M.");

    Instant now = Instant.now();
    Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0);
    Record r2 = new RRSIGRecord(n, DClass.IN, 0, Type.A, 1, 0, now, now, 10, n, new byte[0]);
    assertThat(r1.sameRRset(r2)).isTrue();
    assertThat(r2.sameRRset(r1)).isTrue();

    r1 = Record.newRecord(n, Type.A, DClass.HS, 0);
    r2 = new RRSIGRecord(n, DClass.IN, 0, Type.A, 1, 0, now, now, 10, n, new byte[0]);
    assertThat(r1.sameRRset(r2)).isFalse();
    assertThat(r2.sameRRset(r1)).isFalse();

    r1 = Record.newRecord(n, Type.A, DClass.IN, 0);
    r2 = new RRSIGRecord(m, DClass.IN, 0, Type.A, 1, 0, now, now, 10, n, new byte[0]);
    assertThat(r1.sameRRset(r2)).isFalse();
    assertThat(r2.sameRRset(r1)).isFalse();
  }

  @Test
  void equals() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name n2 = Name.fromString("my.n.");
    Name m = Name.fromString("My.M.");

    Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0);

    assertThat(r1).isNotEqualTo(null);
    assertThat(new Object()).isNotEqualTo(r1);

    Record r2 = Record.newRecord(n, Type.A, DClass.IN, 0);
    assertThat(r2).isEqualTo(r1);
    assertThat(r1).isEqualTo(r2);

    r2 = Record.newRecord(n2, Type.A, DClass.IN, 0);
    assertThat(r2).isEqualTo(r1);
    assertThat(r1).isEqualTo(r2);

    r2 = Record.newRecord(n2, Type.A, DClass.IN, 0xABCDE);
    assertThat(r2).isEqualTo(r1);
    assertThat(r1).isEqualTo(r2);

    r2 = Record.newRecord(m, Type.A, DClass.IN, 0xABCDE);
    assertThat(r2).isNotEqualTo(r1);
    assertThat(r1).isNotEqualTo(r2);

    r2 = Record.newRecord(n2, Type.MX, DClass.IN, 0xABCDE);
    assertThat(r2).isNotEqualTo(r1);
    assertThat(r1).isNotEqualTo(r2);

    r2 = Record.newRecord(n2, Type.A, DClass.CHAOS, 0xABCDE);
    assertThat(r2).isNotEqualTo(r1);
    assertThat(r1).isNotEqualTo(r2);

    byte[] d1 = {23, 12, 9, (byte) 129};
    byte[] d2 = {(byte) 220, 1, (byte) 131, (byte) 212};

    r1 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);
    r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);

    assertThat(r2).isEqualTo(r1);
    assertThat(r1).isEqualTo(r2);

    r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d2);

    assertThat(r2).isNotEqualTo(r1);
    assertThat(r1).isNotEqualTo(r2);
  }

  @Test
  void test_hashCode() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name n2 = Name.fromString("my.n.");
    Name m = Name.fromString("My.M.");
    byte[] d1 = {23, 12, 9, (byte) 129};
    byte[] d2 = {(byte) 220, 1, (byte) 131, (byte) 212};

    Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);

    // same record has same hash code
    Record r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);
    assertThat(r2).hasSameHashCodeAs(r1);

    // case of names should not matter
    r2 = Record.newRecord(n2, Type.A, DClass.IN, 0xABCDE9, d1);
    assertThat(r2).hasSameHashCodeAs(r1);

    // different names
    r2 = Record.newRecord(m, Type.A, DClass.IN, 0xABCDE9, d1);
    assertThat(r2.hashCode()).isNotEqualTo(r1.hashCode());

    // different class
    r2 = Record.newRecord(n, Type.A, DClass.CHAOS, 0xABCDE9, d1);
    assertThat(r2.hashCode()).isNotEqualTo(r1.hashCode());

    // different TTL does not matter
    r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE, d1);
    assertThat(r2).hasSameHashCodeAs(r1);

    // different data
    r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d2);
    assertThat(r2.hashCode()).isNotEqualTo(r1.hashCode());
  }

  @Test
  void cloneRecord() throws TextParseException {
    Name n = Name.fromString("My.N.");
    byte[] d = {23, 12, 9, (byte) 129};
    Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

    Record r2 = r.cloneRecord();

    assertNotSame(r, r2);
    assertThat(r2).isEqualTo(r);

    r = new SubRecord(n, Type.A, DClass.IN, 0xABCDE9);

    assertThatExceptionOfType(IllegalStateException.class).isThrownBy(r::cloneRecord);
  }

  @Test
  void withName() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name m = Name.fromString("My.M.Name.");
    Name rel = Name.fromString("My.Relative.Name");
    byte[] d = {23, 12, 9, (byte) 129};
    Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

    Record r1 = r.withName(m);

    assertThat(r1.getName()).isEqualTo(m);
    assertThat(r1.getType()).isEqualTo(Type.A);
    assertThat(r1.getDClass()).isEqualTo(DClass.IN);
    assertThat(r1.getTTL()).isEqualTo(0xABCDE9);
    assertThat(((ARecord) r1).getAddress()).isEqualTo(((ARecord) r).getAddress());

    assertThatExceptionOfType(RelativeNameException.class).isThrownBy(() -> r.withName(rel));
  }

  @Test
  void withDClass() throws TextParseException {
    Name n = Name.fromString("My.N.");
    byte[] d = {23, 12, 9, (byte) 129};
    Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

    Record r1 = r.withDClass(DClass.HESIOD, 0x9876);

    assertThat(r1.getName()).isEqualTo(n);
    assertThat(r1.getType()).isEqualTo(Type.A);
    assertThat(r1.getDClass()).isEqualTo(DClass.HESIOD);
    assertThat(r1.getTTL()).isEqualTo(0x9876);
    assertThat(((ARecord) r1).getAddress()).isEqualTo(((ARecord) r).getAddress());
  }

  @Test
  void setTTL() throws TextParseException, UnknownHostException {
    Name n = Name.fromString("My.N.");
    byte[] d = {23, 12, 9, (byte) 129};
    InetAddress exp = InetAddress.getByName("23.12.9.129");
    Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

    assertThat(r.getTTL()).isEqualTo(0xABCDE9);

    r.setTTL(0x9876);

    assertThat(r.getName()).isEqualTo(n);
    assertThat(r.getType()).isEqualTo(Type.A);
    assertThat(r.getDClass()).isEqualTo(DClass.IN);
    assertThat(r.getTTL()).isEqualTo(0x9876);
    assertThat(((ARecord) r).getAddress()).isEqualTo(exp);
  }

  @Test
  void compareTo() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name n2 = Name.fromString("my.n.");
    Name m = Name.fromString("My.M.");
    byte[] d = {23, 12, 9, (byte) 129};
    byte[] d2 = {23, 12, 9, (byte) 128};
    Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);
    Record r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

    assertThat(r1).isEqualByComparingTo(r1);
    assertThat(r1).isEqualByComparingTo(r2);
    assertThat(r2).isEqualByComparingTo(r1);

    // name comparison should be canonical
    r2 = Record.newRecord(n2, Type.A, DClass.IN, 0xABCDE9, d);
    assertThat(r1).isEqualByComparingTo(r2);
    assertThat(r2).isEqualByComparingTo(r1);

    // different name
    r2 = Record.newRecord(m, Type.A, DClass.IN, 0xABCDE9, d);
    assertThat(r1.compareTo(r2)).isEqualTo(n.compareTo(m));
    assertThat(r2.compareTo(r1)).isEqualTo(m.compareTo(n));

    // different DClass
    r2 = Record.newRecord(n, Type.A, DClass.CHAOS, 0xABCDE9, d);
    assertThat(r1.compareTo(r2)).isEqualTo(DClass.IN - DClass.CHAOS);
    assertThat(r2.compareTo(r1)).isEqualTo(DClass.CHAOS - DClass.IN);

    // different Type
    r2 = Record.newRecord(n, Type.NS, DClass.IN, 0xABCDE9, m.toWire());
    assertThat(r1.compareTo(r2)).isEqualTo(Type.A - Type.NS);
    assertThat(r2.compareTo(r1)).isEqualTo(Type.NS - Type.A);

    // different data (same length)
    r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d2);
    assertThat(r1.compareTo(r2)).isOne();
    assertThat(r2.compareTo(r1)).isEqualTo(-1);

    // different data (one a prefix of the other)
    m = Name.fromString("My.N.L.");
    r1 = Record.newRecord(n, Type.NS, DClass.IN, 0xABCDE9, n.toWire());
    r2 = Record.newRecord(n, Type.NS, DClass.IN, 0xABCDE9, m.toWire());
    assertThat(r1.compareTo(r2)).isEqualTo(-1);
    assertThat(r2.compareTo(r1)).isOne();
  }

  @Test
  void getAdditionalName() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Record r = new SubRecord(n, Type.A, DClass.IN, 0xABCDE9);

    assertThat(r.getAdditionalName()).isNull();
  }

  @Test
  void checkU8() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Record.checkU8("field", -1));
    assertThat(Record.checkU8("field", 0)).isZero();
    assertThat(Record.checkU8("field", 0x9D)).isEqualTo(0x9D);
    assertThat(Record.checkU8("field", 0xFF)).isEqualTo(0xFF);
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Record.checkU8("field", 0x100));
  }

  @Test
  void checkU16() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Record.checkU16("field", -1));
    assertThat(Record.checkU16("field", 0)).isZero();
    assertThat(Record.checkU16("field", 0x9DA1)).isEqualTo(0x9DA1);
    assertThat(Record.checkU16("field", 0xFFFF)).isEqualTo(0xFFFF);
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Record.checkU16("field", 0x10000));
  }

  @Test
  void checkU32() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Record.checkU32("field", -1));
    assertThat(Record.checkU32("field", 0)).isZero();
    assertThat(Record.checkU32("field", 0x9DA1F02DL)).isEqualTo(0x9DA1F02DL);
    assertThat(Record.checkU32("field", 0xFFFFFFFFL)).isEqualTo(0xFFFFFFFFL);
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> Record.checkU32("field", 0x100000000L));
  }

  @Test
  void checkName() throws TextParseException {
    Name n = Name.fromString("My.N.");
    Name m = Name.fromString("My.m");

    assertThat(Record.checkName("field", n)).isEqualTo(n);

    assertThatExceptionOfType(RelativeNameException.class)
        .isThrownBy(() -> Record.checkName("field", m));
  }

  @Test
  void testAllTypesHaveNoArgConstructor() {
    for (int i = 1; i < 65535; i++) {
      Supplier<Record> proto = Type.getFactory(i);
      if (proto != null) {
        assertThatCode(() -> assertThat(proto.get()).isNotNull())
            .withFailMessage(
                String.format(
                    "Record type %s, (%d, %s) seems to have no or invalid 0arg ctor",
                    Type.string(i), i, proto.getClass().getSimpleName()))
            .doesNotThrowAnyException();
      }
    }
  }

  @Test
  void testSerializable() throws IOException {
    for (int i = 1; i < 65535; i++) {
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
          if (Type.getFactory(i) != null) {
            Record expected = Record.newRecord(Name.root, i, DClass.IN);
            assertThatCode(
                    () -> {
                      oos.writeObject(expected);
                      try (ObjectInputStream ois =
                          new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
                        Record actual = (Record) ois.readObject();
                        assertThat(actual).isEqualTo(expected);
                      }
                    })
                .withFailMessage(
                    String.format(
                        "Record type %s (%d, %s) failed to (de)serialize",
                        Type.string(i), i, expected.getClass().getSimpleName()))
                .doesNotThrowAnyException();
          }
        }
      }
    }
  }

  // https://github.com/dnsjava/dnsjava/issues/254
  @Test
  void testEmptyTXTSerialization() throws IOException {
    Name recordName = Name.fromString("name.name.");
    Record r = Record.fromString(recordName, Type.TXT, DClass.IN, 0, "", recordName);
    assertThat(r).hasToString("name.name.\t\t0\tIN\tTXT\t\"\"");
  }
}

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

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class RecordTest
{
    private static class SubRecord extends Record
    {
	SubRecord(){}

	SubRecord(Name name, int type, int dclass, long ttl)
	{
	    super(name, type, dclass, ttl);
	}

	@Override
	public Record getObject()
	{
	    return null;
	}

	@Override
	public void rrFromWire(DNSInput in) {}

	@Override
	public String rrToString()
	{
	    return "{SubRecord: rrToString}";
	}

	@Override
	public void rdataFromString(Tokenizer t, Name origin) {}

	@Override
	public void rrToWire(DNSOutput out, Compression c, boolean canonical) {}

	// makes it callable by test code
	public static byte[] byteArrayFromString(String in) throws TextParseException
	{
	    return Record.byteArrayFromString(in);
	}

	// make it callable by test code
	public static String byteArrayToString(byte[] in, boolean quote)
	{
	    return Record.byteArrayToString(in, quote);
	}

	// make it callable by test code
	public static String unknownToString(byte[] in)
	{
	    return Record.unknownToString(in);
	}

	@Override
	public Object clone() throws CloneNotSupportedException
	{
	    throw new CloneNotSupportedException();
	}
    }

    @Test
    void test_ctor_0arg()
    {
	SubRecord sr = new SubRecord();
	assertNull(sr.getName());
	assertEquals(0, sr.getType());
	assertEquals(0, sr.getTTL());
	assertEquals(0, sr.getDClass());
    }

    @Test
    void test_ctor_4arg() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	int t = Type.A;
	int d = DClass.IN;
	long ttl = 0xABCDEL;

	SubRecord r = new SubRecord(n, t, d, ttl);
	assertEquals(n, r.getName());
	assertEquals(t, r.getType());
	assertEquals(d, r.getDClass());
	assertEquals(ttl, r.getTTL());
    }

    @Test
    void test_ctor_4arg_invalid() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	Name r = Name.fromString("my.relative.name");
	int t = Type.A;
	int d = DClass.IN;
	long ttl = 0xABCDEL;

	try {
	    new SubRecord(r, t, d, ttl);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}

	try {
	    new SubRecord(n, -1, d, ttl);
	    fail("InvalidTypeException not thrown");
	}
	catch( InvalidTypeException e ){}

	try {
	    new SubRecord(n, t, -1, ttl);
	    fail("InvalidDClassException not thrown");
	}
	catch( InvalidDClassException e ){}

	try {
	    new SubRecord(n, t, d, -1);
	    fail("InvalidTTLException not thrown");
	}
	catch( InvalidTTLException e ){}
    }

    @Test
    void test_newRecord_3arg() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	Name r = Name.fromString("my.relative.name");
	int t = Type.A;
	int d = DClass.IN;

	Record rec = Record.newRecord(n, t, d);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(0, rec.getTTL());

	try {
	    Record.newRecord(r, t, d);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }

    @Test
    void test_newRecord_4arg() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	Name r = Name.fromString("my.relative.name");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;

	Record rec = Record.newRecord(n, t, d, ttl);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());

	try {
	    Record.newRecord(r, t, d, ttl);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }

    @Test
    void test_newRecord_5arg() throws TextParseException,
					     UnknownHostException
    {
	Name n = Name.fromString("my.name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;
	byte[] data = new byte[] { (byte)123, (byte)232, (byte)0, (byte)255 };
	InetAddress exp = InetAddress.getByName("123.232.0.255");

	Record rec = Record.newRecord(n, t, d, ttl, data);
	assertTrue(rec instanceof ARecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());
	assertEquals(exp, ((ARecord)rec).getAddress());
    }

    @Test
    void test_newRecord_6arg() throws TextParseException,
					     UnknownHostException
    {
	Name n = Name.fromString("my.name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;
	byte[] data = new byte[] { (byte)123, (byte)232, (byte)0, (byte)255 };
	InetAddress exp = InetAddress.getByName("123.232.0.255");

	Record rec = Record.newRecord(n, t, d, ttl, 0, null);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());

	rec = Record.newRecord(n, t, d, ttl, data.length, data);
	assertTrue(rec instanceof ARecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());
	assertEquals(exp, ((ARecord)rec).getAddress());
	
	rec = Record.newRecord(n, Type.NIMLOC, d, ttl, data.length, data);
	assertTrue(rec instanceof UNKRecord);
	assertEquals(n, rec.getName());
	assertEquals(Type.NIMLOC, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());
	    assertArrayEquals(data, ((UNKRecord) rec).getData());
    }

    @Test
    void test_newRecord_6arg_invalid() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	Name r = Name.fromString("my.relative.name");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;
	byte[] data = new byte[] { (byte)123, (byte)232, (byte)0, (byte)255 };

	assertNull(Record.newRecord(n, t, d, ttl, 0, new byte[ 0 ]));
	assertNull(Record.newRecord(n, t, d, ttl, 1, new byte[ 0 ]));
	assertNull(Record.newRecord(n, t, d, ttl, data.length+1, data));
	assertNull(Record.newRecord(n, t, d, ttl, 5, new byte[] { data[0], data[1], data[2], data[3], 0 }));
	try {
	    Record.newRecord(r, t, d, ttl, 0, null);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}

    }

    @Test
    void test_fromWire() throws IOException {
	Name n = Name.fromString("my.name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;
	byte[] data = new byte[] { (byte)123, (byte)232, (byte)0, (byte)255 };
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
	assertTrue(rec instanceof ARecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());
	assertEquals(exp, ((ARecord)rec).getAddress());

	in = new DNSInput(out.toByteArray());
	rec = Record.fromWire(in, Section.QUESTION, false);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(0, rec.getTTL());

	in = new DNSInput(out.toByteArray());
	rec = Record.fromWire(in, Section.QUESTION);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(0, rec.getTTL());

	rec = Record.fromWire(out.toByteArray(), Section.QUESTION);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(0, rec.getTTL());

	out = new DNSOutput();
	n.toWire(out, null);
	out.writeU16(t);
	out.writeU16(d);
	out.writeU32(ttl);
	out.writeU16(0);

	in = new DNSInput(out.toByteArray());

	rec = Record.fromWire(in, Section.ANSWER, true);
	assertTrue(rec instanceof EmptyRecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());

    }

    @Test
    void test_toWire() throws IOException {
	Name n = Name.fromString("my.name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;
	byte[] data = new byte[] { (byte)123, (byte)232, (byte)0, (byte)255 };

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

	rec.toWire(out, Section.ANSWER, null);

	byte[] after = out.toByteArray();

	    assertArrayEquals(exp, after);

	// an equivalent call
	after = rec.toWire(Section.ANSWER);
	    assertArrayEquals(exp, after);

	// a QUESTION entry
	out = new DNSOutput();
	n.toWire(out, null);
	out.writeU16(t);
	out.writeU16(d);

	exp = out.toByteArray();
	out = new DNSOutput();
	rec.toWire(out, Section.QUESTION, null);
	after = out.toByteArray();

	    assertArrayEquals(exp, after);

    }

    @Test
    void test_toWireCanonical() throws IOException {
	Name n = Name.fromString("My.Name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xDBE8;
	byte[] data = new byte[] { (byte)123, (byte)232, (byte)0, (byte)255 };

	DNSOutput out = new DNSOutput();
	n.toWireCanonical(out);
	out.writeU16(t);
	out.writeU16(d);
	out.writeU32(ttl);
	out.writeU16(data.length);
	out.writeByteArray(data);

	byte[] exp = out.toByteArray();

	Record rec = Record.newRecord(n, t, d, ttl, data.length, data);

	byte[] after = rec.toWireCanonical();
	    assertArrayEquals(exp, after);
    }

    @Test
    void test_rdataToWireCanonical() throws IOException {
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
	assertTrue(rec instanceof NSRecord);

	byte[] after = rec.rdataToWireCanonical();

	    assertArrayEquals(exp, after);
    }

    @Test
    void test_rdataToString() throws IOException {
	Name n = Name.fromString("My.Name.");
	Name n2 = Name.fromString("My.Second.Name.");
	int t = Type.NS;
	int d = DClass.IN;
	int ttl = 0xABE99;
	DNSOutput out = new DNSOutput();
	n2.toWire(out, null);
	byte[] data = out.toByteArray();

	Record rec = Record.newRecord(n, t, d, ttl, data.length, data);
	assertTrue(rec instanceof NSRecord);
	assertEquals(rec.rrToString(), rec.rdataToString());
    }

    @Test
    void test_toString() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name n2 = Name.fromString("My.Second.Name.");
	int t = Type.NS;
	int d = DClass.IN;
	int ttl = 0xABE99;
	DNSOutput o = new DNSOutput();
	n2.toWire(o, null);
	byte[] data = o.toByteArray();

	Record rec = Record.newRecord(n, t, d, ttl, data.length, data);
	String out = rec.toString();

	    assertTrue(out.contains(n.toString()));
	    assertTrue(out.contains(n2.toString()));
	    assertTrue(out.contains("NS"));
	    assertTrue(out.contains("IN"));
	    assertTrue(out.contains(ttl + ""));

	Options.set("BINDTTL");

	out = rec.toString();
	    assertTrue(out.contains(n.toString()));
	    assertTrue(out.contains(n2.toString()));
	    assertTrue(out.contains("NS"));
	    assertTrue(out.contains("IN"));
	    assertTrue(out.contains(TTL.format(ttl)));

	Options.set("noPrintIN");
	out = rec.toString();
	    assertTrue(out.contains(n.toString()));
	    assertTrue(out.contains(n2.toString()));
	    assertTrue(out.contains("NS"));
	    assertFalse(out.contains("IN"));
	    assertTrue(out.contains(TTL.format(ttl)));
    }

    @Test
    void test_byteArrayFromString() throws TextParseException
    {
	String in = "the 98 \" \' quick 0xAB brown";
	byte[] out = SubRecord.byteArrayFromString(in);
	    assertArrayEquals(in.getBytes(), out);

	in = " \\031Aa\\;\\\"\\\\~\\127\\255";
	byte[] exp = new byte[] { ' ', 0x1F, 'A', 'a', ';', '"', '\\', 0x7E, 0x7F, (byte)0xFF };
	out = SubRecord.byteArrayFromString(in);
	    assertArrayEquals(exp, out);
    }

    @Test
    void test_byteArrayFromString_invalid()
    {
	StringBuilder b = new StringBuilder();
	for( int i=0; i<257; ++i){
	    b.append('A');
	}
	try {
	    SubRecord.byteArrayFromString(b.toString());
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}

	try {
	    SubRecord.byteArrayFromString("\\256");
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}
	try {
	    SubRecord.byteArrayFromString("\\25a");
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}
	try {
	    SubRecord.byteArrayFromString("\\25");
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}

	b.append("\\233");
	try {
	    SubRecord.byteArrayFromString(b.toString());
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}
	
    }

    @Test
    void test_byteArrayToString()
    {
	byte[] in = new byte[] { ' ', 0x1F, 'A', 'a', ';', '"', '\\', 0x7E, 0x7F, (byte)0xFF };
	String exp = "\" \\031Aa;\\\"\\\\~\\127\\255\"";
	assertEquals(exp, SubRecord.byteArrayToString(in, true));
    }

    @Test
    void test_unknownToString()
    {
	byte[] data = new byte[] { (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, (byte)0x9A,
				   (byte)0xBC, (byte)0xDE, (byte)0xFF };
	String out = SubRecord.unknownToString(data);

	    assertTrue(out.contains("" + data.length));
	    assertTrue(out.contains("123456789ABCDEFF"));
    }

    @Test
    void test_fromString() throws IOException {
	Name n = Name.fromString("My.N.");
	Name n2 = Name.fromString("My.Second.Name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xABE99;
	String sa = "191.234.43.10";
	InetAddress addr = InetAddress.getByName(sa);
	byte[] b = new byte[] { (byte)191, (byte)234, (byte)43, (byte)10 };

	Tokenizer st = new Tokenizer(sa);
	Record rec = Record.fromString(n, t, d, ttl, st, n2);
	assertTrue(rec instanceof ARecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());
	assertEquals(addr, ((ARecord)rec).getAddress());

	String unkData = SubRecord.unknownToString(b);
	st = new Tokenizer(unkData);
	rec = Record.fromString(n, t, d, ttl, st, n2);
	assertTrue(rec instanceof ARecord);
	assertEquals(n, rec.getName());
	assertEquals(t, rec.getType());
	assertEquals(d, rec.getDClass());
	assertEquals(ttl, rec.getTTL());
	assertEquals(addr, ((ARecord)rec).getAddress());
    }

    @Test
    void test_fromString_invalid() throws IOException {
	Name n = Name.fromString("My.N.");
	Name rel = Name.fromString("My.R");
	Name n2 = Name.fromString("My.Second.Name.");
	int t = Type.A;
	int d = DClass.IN;
	int ttl = 0xABE99;
	InetAddress addr = InetAddress.getByName("191.234.43.10");

	Tokenizer st = new Tokenizer("191.234.43.10");

	try {
	    Record.fromString(rel, t, d, ttl, st, n2);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}

	st = new Tokenizer("191.234.43.10 another_token");
	try {
	    Record.fromString(n, t, d, ttl, st, n2);
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}

	st = new Tokenizer("\\# 100 ABCDE");
	try {
	    Record.fromString(n, t, d, ttl, st, n2);
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}

	try {
	    Record.fromString(n, t, d, ttl, "\\# 100", n2);
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}
    }

    @Test
    void test_getRRsetType() throws TextParseException
    {
	Name n = Name.fromString("My.N.");

	Record r = Record.newRecord(n, Type.A, DClass.IN, 0);
	assertEquals(Type.A, r.getRRsetType());

	r = new RRSIGRecord(n, DClass.IN, 0, Type.A, 1, 0, new Date(),
			    new Date(), 10, n, new byte[ 0 ]);
	assertEquals(Type.A, r.getRRsetType());

	// create an "EmptyRecord" instance with RRSIG type. As it has no RDATA,
	// it cannot return the covered type
	r = Record.newRecord(n, Type.RRSIG, DClass.IN, 86400, 0, null);
	assertEquals(Type.RRSIG, r.getRRsetType());
    }

    @Test
    void test_sameRRset() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name m = Name.fromString("My.M.");

	Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0);
	Record r2 = new RRSIGRecord(n, DClass.IN, 0, Type.A, 1, 0, new Date(),
				    new Date(), 10, n, new byte[ 0 ]);
	assertTrue(r1.sameRRset(r2));
	assertTrue(r2.sameRRset(r1));

	r1 = Record.newRecord(n, Type.A, DClass.HS, 0);
	r2 = new RRSIGRecord(n, DClass.IN, 0, Type.A, 1, 0, new Date(),
			     new Date(), 10, n, new byte[ 0 ]);
	assertFalse(r1.sameRRset(r2));
	assertFalse(r2.sameRRset(r1));

	r1 = Record.newRecord(n, Type.A, DClass.IN, 0);
	r2 = new RRSIGRecord(m, DClass.IN, 0, Type.A, 1, 0, new Date(),
			     new Date(), 10, n, new byte[ 0 ]);
	assertFalse(r1.sameRRset(r2));
	assertFalse(r2.sameRRset(r1));
    }

    @Test
    void test_equals() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name n2 = Name.fromString("my.n.");
	Name m = Name.fromString("My.M.");

	Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0);

	    assertNotEquals(null, r1);
	    assertNotEquals(r1, new Object());

	Record r2 = Record.newRecord(n, Type.A, DClass.IN, 0);
	assertEquals(r1, r2);
	assertEquals(r2, r1);

	r2 = Record.newRecord(n2, Type.A, DClass.IN, 0);
	assertEquals(r1, r2);
	assertEquals(r2, r1);

	r2 = Record.newRecord(n2, Type.A, DClass.IN, 0xABCDE);
	assertEquals(r1, r2);
	assertEquals(r2, r1);

	r2 = Record.newRecord(m, Type.A, DClass.IN, 0xABCDE);
	    assertNotEquals(r1, r2);
	    assertNotEquals(r2, r1);

	r2 = Record.newRecord(n2, Type.MX, DClass.IN, 0xABCDE);
	    assertNotEquals(r1, r2);
	    assertNotEquals(r2, r1);

	r2 = Record.newRecord(n2, Type.A, DClass.CHAOS, 0xABCDE);
	    assertNotEquals(r1, r2);
	    assertNotEquals(r2, r1);

	byte[] d1 = new byte[] { 23, 12, 9, (byte)129 };
	byte[] d2 = new byte[] { (byte)220, 1, (byte)131, (byte)212 };

	r1 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);
	r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);

	assertEquals(r1, r2);
	assertEquals(r2, r1);

	r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d2);

	    assertNotEquals(r1, r2);
	    assertNotEquals(r2, r1);
    }

    @Test
    void test_hashCode() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name n2 = Name.fromString("my.n.");
	Name m = Name.fromString("My.M.");
	byte[] d1 = new byte[] { 23, 12, 9, (byte)129 };
	byte[] d2 = new byte[] { (byte)220, 1, (byte)131, (byte)212 };

	Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);

	// same record has same hash code
	Record r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d1);
	assertEquals(r1.hashCode(), r2.hashCode());

	// case of names should not matter
	r2 = Record.newRecord(n2, Type.A, DClass.IN, 0xABCDE9, d1);
	assertEquals(r1.hashCode(), r2.hashCode());

	// different names
	r2 = Record.newRecord(m, Type.A, DClass.IN, 0xABCDE9, d1);
	    assertNotEquals(r1.hashCode(), r2.hashCode());

	// different class
	r2 = Record.newRecord(n, Type.A, DClass.CHAOS, 0xABCDE9, d1);
	    assertNotEquals(r1.hashCode(), r2.hashCode());

	// different TTL does not matter
	r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE, d1);
	assertEquals(r1.hashCode(), r2.hashCode());

	// different data
	r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d2);
	    assertNotEquals(r1.hashCode(), r2.hashCode());
    }

    @Test
    void test_cloneRecord() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	byte[] d = new byte[] { 23, 12, 9, (byte)129 };
	Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

	Record r2 = r.cloneRecord();

	assertNotSame(r, r2);
	assertEquals(r, r2);

	r = new SubRecord(n, Type.A, DClass.IN, 0xABCDE9);

	try {
	    r.cloneRecord();
	    fail("IllegalStateException not thrown");
	}
	catch( IllegalStateException e ){}
    }

    @Test
    void test_withName() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name m = Name.fromString("My.M.Name.");
	Name rel = Name.fromString("My.Relative.Name");
	byte[] d = new byte[] { 23, 12, 9, (byte)129 };
	Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

	Record r1 = r.withName(m);
	
	assertEquals(m, r1.getName());
	assertEquals(Type.A, r1.getType());
	assertEquals(DClass.IN, r1.getDClass());
	assertEquals(0xABCDE9, r1.getTTL());
	assertEquals(((ARecord)r).getAddress(), ((ARecord)r1).getAddress());

	try {
	    r.withName(rel);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }

    @Test
    void test_withDClass() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	byte[] d = new byte[] { 23, 12, 9, (byte)129 };
	Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

	Record r1 = r.withDClass(DClass.HESIOD, 0x9876);
	
	assertEquals(n, r1.getName());
	assertEquals(Type.A, r1.getType());
	assertEquals(DClass.HESIOD, r1.getDClass());
	assertEquals(0x9876, r1.getTTL());
	assertEquals(((ARecord)r).getAddress(), ((ARecord)r1).getAddress());
    }

    @Test
    void test_setTTL() throws TextParseException,
				     UnknownHostException
    {
	Name n = Name.fromString("My.N.");
	byte[] d = new byte[] { 23, 12, 9, (byte)129 };
	InetAddress exp = InetAddress.getByName("23.12.9.129");
	Record r = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);

	assertEquals(0xABCDE9, r.getTTL());

	r.setTTL(0x9876);

	assertEquals(n, r.getName());
	assertEquals(Type.A, r.getType());
	assertEquals(DClass.IN, r.getDClass());
	assertEquals(0x9876, r.getTTL());
	assertEquals(exp, ((ARecord)r).getAddress());
    }

    @Test
    void test_compareTo() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name n2 = Name.fromString("my.n.");
	Name m = Name.fromString("My.M.");
	byte[] d = new byte[] { 23, 12, 9, (byte)129 };
	byte[] d2 = new byte[] { 23, 12, 9, (byte)128 };
	Record r1 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);
	Record r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d);
	
	assertEquals(0, r1.compareTo(r1));

	assertEquals(0, r1.compareTo(r2));
	assertEquals(0, r2.compareTo(r1));

	// name comparison should be canonical
	r2 = Record.newRecord(n2, Type.A, DClass.IN, 0xABCDE9, d);
	assertEquals(0, r1.compareTo(r2));
	assertEquals(0, r2.compareTo(r1));

	// different name
	r2 = Record.newRecord(m, Type.A, DClass.IN, 0xABCDE9, d);
	assertEquals(n.compareTo(m), r1.compareTo(r2));
	assertEquals(m.compareTo(n), r2.compareTo(r1));

	// different DClass
	r2 = Record.newRecord(n, Type.A, DClass.CHAOS, 0xABCDE9, d);
	assertEquals(DClass.IN-DClass.CHAOS, r1.compareTo(r2));
	assertEquals(DClass.CHAOS-DClass.IN, r2.compareTo(r1));

	// different Type
	r2 = Record.newRecord(n, Type.NS, DClass.IN, 0xABCDE9, m.toWire());
	assertEquals(Type.A-Type.NS, r1.compareTo(r2));
	assertEquals(Type.NS-Type.A, r2.compareTo(r1));

	// different data (same length)
	r2 = Record.newRecord(n, Type.A, DClass.IN, 0xABCDE9, d2);
	assertEquals(1, r1.compareTo(r2));
	assertEquals(-1, r2.compareTo(r1));

	// different data (one a prefix of the other)
	m = Name.fromString("My.N.L.");
	r1 = Record.newRecord(n, Type.NS, DClass.IN, 0xABCDE9, n.toWire());
	r2 = Record.newRecord(n, Type.NS, DClass.IN, 0xABCDE9, m.toWire());
	assertEquals(-1, r1.compareTo(r2));
	assertEquals(1, r2.compareTo(r1));
    }

    @Test
    void test_getAdditionalName() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Record r = new SubRecord(n, Type.A, DClass.IN, 0xABCDE9);

	assertNull(r.getAdditionalName());
    }

    @Test
    void test_checkU8()
    {
	try {Record.checkU8("field", -1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	assertEquals(0, Record.checkU8("field", 0));
	assertEquals(0x9D, Record.checkU8("field", 0x9D));
	assertEquals(0xFF, Record.checkU8("field", 0xFF));
	try {Record.checkU8("field", 0x100); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
    }

    @Test
    void test_checkU16()
    {
	try {Record.checkU16("field", -1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	assertEquals(0, Record.checkU16("field", 0));
	assertEquals(0x9DA1, Record.checkU16("field", 0x9DA1));
	assertEquals(0xFFFF, Record.checkU16("field", 0xFFFF));
	try {Record.checkU16("field", 0x10000); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
    }

    @Test
    void test_checkU32()
    {
	try {Record.checkU32("field", -1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	assertEquals(0, Record.checkU32("field", 0));
	assertEquals(0x9DA1F02DL, Record.checkU32("field", 0x9DA1F02DL));
	assertEquals(0xFFFFFFFFL, Record.checkU32("field", 0xFFFFFFFFL));
	try {Record.checkU32("field", 0x100000000L); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
    }

    @Test
    void test_checkName() throws TextParseException
    {
	Name n = Name.fromString("My.N.");
	Name m = Name.fromString("My.m");

	assertEquals(n, Record.checkName("field", n));

	try {
	    Record.checkName("field", m);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }
}

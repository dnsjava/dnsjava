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

import	java.io.IOException;
import	java.util.Arrays;
import	junit.framework.TestCase;
import	org.xbill.DNS.utils.base64;

public class KEYBaseTest extends TestCase
{
    private static class TestClass extends KEYBase
    {
	public TestClass(){}

	public TestClass(Name name, int type, int dclass, long ttl,
			 int flags, int proto, int alg, byte[] key )
	{
	    super(name, type, dclass, ttl, flags, proto, alg, key);
	}
	
	public Record getObject()
	{
	    return null;
	}

	void rdataFromString(Tokenizer st, Name origin) throws IOException
	{
	}
    }

    public void test_ctor() throws TextParseException
    {
	TestClass tc = new TestClass();
	assertEquals(0, tc.getFlags());
	assertEquals(0, tc.getProtocol());
	assertEquals(0, tc.getAlgorithm());
	assertNull(tc.getKey());

	Name n = Name.fromString("my.name.");
	byte[] key = new byte[] { 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };

	tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, 0xE, key);

	assertSame(n, tc.getName());
	assertEquals(Type.KEY, tc.getType());
	assertEquals(DClass.IN, tc.getDClass());
	assertEquals(100L, tc.getTTL());
	assertEquals(0xFF, tc.getFlags());
	assertEquals(0xF, tc.getProtocol());
	assertEquals(0xE, tc.getAlgorithm());
	assertTrue(Arrays.equals(key, tc.getKey()));
    }

    public void test_rrFromWire() throws IOException
    {
	byte[] raw = new byte[] { (byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0x19, 1, 2, 3, 4, 5 };
	DNSInput in = new DNSInput(raw);
	
	TestClass tc = new TestClass();
	tc.rrFromWire(in);

	assertEquals(0xABCD, tc.getFlags());
	assertEquals(0xEF, tc.getProtocol());
	assertEquals(0x19, tc.getAlgorithm());
	assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 }, tc.getKey()));


	raw = new byte[] { (byte)0xBA, (byte)0xDA, (byte)0xFF, (byte)0x28 };
	in = new DNSInput(raw);
	
	tc = new TestClass();
	tc.rrFromWire(in);

	assertEquals(0xBADA, tc.getFlags());
	assertEquals(0xFF, tc.getProtocol());
	assertEquals(0x28, tc.getAlgorithm());
	assertNull(tc.getKey());
    }

    public void test_rrToString() throws IOException, TextParseException
    {
	Name n = Name.fromString("my.name.");
	byte[] key = new byte[] { 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };

	TestClass tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, 0xE, null);

	String out = tc.rrToString();

	assertEquals("255 15 14", out);

	tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, 0xE, key);
	out = tc.rrToString();

	assertEquals("255 15 14 " + base64.toString(key), out);

	Options.set("multiline");
	out = tc.rrToString();
	assertEquals("255 15 14 (\n\t" + base64.toString(key) + " ) ; key_tag = 18509", out);

	Options.unset("multiline");
    }

    public void test_getFootprint() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	byte[] key = new byte[] { 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };

	TestClass tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0xFF, 0xF, DNSSEC.Algorithm.RSAMD5, key);
	
	int foot = tc.getFootprint();
	// second-to-last and third-to-last bytes of key for RSAMD5
	assertEquals(0xD0E, foot);
	assertEquals(foot, tc.getFootprint());

	// key with an odd number of bytes
	tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0x89AB, 0xCD, 0xEF, new byte [] { 0x12, 0x34, 0x56 } );

	// rrToWire gives: { 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56 }
	// 89AB + CDEF + 1234 + 5600 = 1BCFE
	// 1BFCE + 1 = 1BFCF & FFFF = BFCF
	foot = tc.getFootprint();
	assertEquals(0xBFCF, foot);
	assertEquals(foot, tc.getFootprint());

	// empty
	tc = new TestClass();
	assertEquals(0, tc.getFootprint());
    }

    public void test_rrToWire() throws IOException, TextParseException
    {
	Name n = Name.fromString("my.name.");
	byte[] key = new byte[] { 0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
				  0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };

	TestClass tc = new TestClass(n, Type.KEY, DClass.IN, 100L, 0x7689, 0xAB, 0xCD, key);
       
	byte[] exp = new byte[] { (byte)0x76, (byte)0x89, (byte)0xAB, (byte)0xCD, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

	DNSOutput o = new DNSOutput();

	// canonical
	tc.rrToWire(o, null, true);
	assertTrue(Arrays.equals(exp, o.toByteArray()));

	// not canonical
	o = new DNSOutput();
	tc.rrToWire(o, null, false);
	assertTrue(Arrays.equals(exp, o.toByteArray()));
    }
}

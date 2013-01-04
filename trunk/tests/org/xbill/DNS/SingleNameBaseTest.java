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
import	junit.framework.TestCase;

public class SingleNameBaseTest extends TestCase
{
    private void assertEquals( byte[] exp, byte[] act )
    {
	assertTrue(java.util.Arrays.equals(exp, act));
    }

    private static class TestClass extends SingleNameBase
    {
	public TestClass(){}

	public TestClass(Name name, int type, int dclass, long ttl)
	{
	    super(name, type, dclass, ttl);
	}
	
	public TestClass(Name name, int type, int dclass, long ttl, Name singleName, String desc )
	{
	    super(name, type, dclass, ttl, singleName, desc);
	}
	
	public Name getSingleName()
	{
	    return super.getSingleName();
	}

	public Record getObject()
	{
	    return null;
	}
    }

    public void test_ctor() throws TextParseException
    {
	TestClass tc = new TestClass();
	assertNull(tc.getSingleName());

	Name n = Name.fromString("my.name.");
	Name sn = Name.fromString("my.single.name.");

	tc = new TestClass(n, Type.A, DClass.IN, 100L);

	assertSame(n, tc.getName());
	assertEquals(Type.A, tc.getType());
	assertEquals(DClass.IN, tc.getDClass());
	assertEquals(100L, tc.getTTL());

	tc = new TestClass(n, Type.A, DClass.IN, 100L, sn, "The Description");

	assertSame(n, tc.getName());
	assertEquals(Type.A, tc.getType());
	assertEquals(DClass.IN, tc.getDClass());
	assertEquals(100L, tc.getTTL());
	assertSame(sn, tc.getSingleName());
    }

    public void test_rrFromWire() throws IOException
    {
	byte[] raw = new byte[] { 2, 'm', 'y', 6, 's', 'i', 'n', 'g', 'l', 'e', 4, 'n', 'a', 'm', 'e', 0 };
	DNSInput in = new DNSInput(raw);
	
	TestClass tc = new TestClass();
	tc.rrFromWire(in);

	Name exp = Name.fromString("my.single.name.");
	assertEquals(exp, tc.getSingleName());
    }

    public void test_rdataFromString() throws IOException
    {
	Name exp = Name.fromString("my.single.name.");

	Tokenizer t = new Tokenizer("my.single.name.");
	TestClass tc = new TestClass();
	tc.rdataFromString(t, null);
	assertEquals(exp, tc.getSingleName());

	t = new Tokenizer("my.relative.name");
	tc = new TestClass();
	try {
	    tc.rdataFromString(t, null);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }

    public void test_rrToString() throws IOException, TextParseException
    {
	Name exp = Name.fromString("my.single.name.");

	Tokenizer t = new Tokenizer("my.single.name.");
	TestClass tc = new TestClass();
	tc.rdataFromString(t, null);
	assertEquals(exp, tc.getSingleName());

	String out = tc.rrToString();
	assertEquals(out, exp.toString());
    }

    public void test_rrToWire() throws IOException, TextParseException
    {
	Name n = Name.fromString("my.name.");
	Name sn = Name.fromString("My.Single.Name.");

	// non-canonical (case sensitive)
	TestClass tc = new TestClass(n, Type.A, DClass.IN, 100L, sn, "The Description");
	byte[] exp = new byte[] { 2, 'M', 'y', 6, 'S', 'i', 'n', 'g', 'l', 'e', 4, 'N', 'a', 'm', 'e', 0 };

	DNSOutput dout = new DNSOutput();
	tc.rrToWire(dout, null, false);
	
	byte[] out = dout.toByteArray();
	assertEquals(exp, out);

	// canonical (lowercase)
	tc = new TestClass(n, Type.A, DClass.IN, 100L, sn, "The Description");
	exp = new byte[] { 2, 'm', 'y', 6, 's', 'i', 'n', 'g', 'l', 'e', 4, 'n', 'a', 'm', 'e', 0 };

	dout = new DNSOutput();
	tc.rrToWire(dout, null, true);
	
	out = dout.toByteArray();
	assertEquals(exp, out);
    }
}

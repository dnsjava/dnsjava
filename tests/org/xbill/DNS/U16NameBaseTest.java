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

public class U16NameBaseTest extends TestCase
{
    private void assertEquals( byte[] exp, byte[] act )
    {
	assertTrue(java.util.Arrays.equals(exp, act));
    }

    private static class TestClass extends U16NameBase
    {
	public TestClass(){}

	public TestClass(Name name, int type, int dclass, long ttl)
	{
	    super(name, type, dclass, ttl);
	}
	
	public TestClass(Name name, int type, int dclass, long ttl, int u16Field,
			 String u16Description, Name nameField, String nameDescription)
	{
	    super(name, type, dclass, ttl, u16Field, u16Description, nameField, nameDescription);
	}
	
	public int getU16Field()
	{
	    return super.getU16Field();
	}

	public Name getNameField()
	{
	    return super.getNameField();
	}

	public Record getObject()
	{
	    return null;
	}
    }

    public void test_ctor_0arg()
    {
	TestClass tc = new TestClass();
	assertNull(tc.getName());
	assertEquals(0, tc.getType());
	assertEquals(0, tc.getDClass());
	assertEquals(0, tc.getTTL());
	assertEquals(0, tc.getU16Field());
	assertNull(tc.getNameField());
    }

    public void test_ctor_4arg() throws TextParseException
    {
	Name n = Name.fromString("My.Name.");

	TestClass tc = new TestClass(n, Type.MX, DClass.IN, 0xBCDA);

	assertSame(n, tc.getName());
	assertEquals(Type.MX, tc.getType());
	assertEquals(DClass.IN, tc.getDClass());
	assertEquals(0xBCDA, tc.getTTL());
	assertEquals(0, tc.getU16Field());
	assertNull(tc.getNameField());
    }

    public void test_ctor_8arg() throws TextParseException
    {
	Name n = Name.fromString("My.Name.");
	Name m = Name.fromString("My.Other.Name.");
	
	TestClass tc = new TestClass(n, Type.MX, DClass.IN, 0xB12FL,
				     0x1F2B, "u16 description",
				     m, "name description");

	assertSame(n, tc.getName());
	assertEquals(Type.MX, tc.getType());
	assertEquals(DClass.IN, tc.getDClass());
	assertEquals(0xB12FL, tc.getTTL());
	assertEquals(0x1F2B, tc.getU16Field());
	assertEquals(m, tc.getNameField());

	// an invalid u16 value
	try {
	    new TestClass(n, Type.MX, DClass.IN, 0xB12FL,
			  0x10000, "u16 description",
			  m, "name description");
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){}

	// a relative name
	Name rel = Name.fromString("My.relative.Name");
	try {
	    new TestClass(n, Type.MX, DClass.IN, 0xB12FL,
			  0x1F2B, "u16 description",
			  rel, "name description");
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
	
    }

    public void test_rrFromWire() throws IOException
    {
	byte[] raw = new byte[] { (byte)0xBC, (byte)0x1F, 2, 'M', 'y', 6, 's', 'i', 'N', 'g', 'l', 'E', 4, 'n', 'A', 'm', 'E', 0 };
	DNSInput in = new DNSInput(raw);
	
	TestClass tc = new TestClass();
	tc.rrFromWire(in);

	Name exp = Name.fromString("My.single.name.");
	assertEquals(0xBC1FL, tc.getU16Field());
	assertEquals(exp, tc.getNameField());
    }

    public void test_rdataFromString() throws IOException
    {
	Name exp = Name.fromString("My.Single.Name.");

	Tokenizer t = new Tokenizer(0x19A2 + " My.Single.Name.");
	TestClass tc = new TestClass();
	tc.rdataFromString(t, null);

	assertEquals(0x19A2, tc.getU16Field());
	assertEquals(exp, tc.getNameField());

	t = new Tokenizer("10 My.Relative.Name");
	tc = new TestClass();
	try {
	    tc.rdataFromString(t, null);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }

    public void test_rrToString() throws IOException, TextParseException
    {
	Name n = Name.fromString("My.Name.");
	Name m = Name.fromString("My.Other.Name.");
	
	TestClass tc = new TestClass(n, Type.MX, DClass.IN, 0xB12FL,
				     0x1F2B, "u16 description",
				     m, "name description");

	String out = tc.rrToString();
	String exp = 0x1F2B + " My.Other.Name.";
	
	assertEquals(exp, out);
    }

    public void test_rrToWire() throws IOException, TextParseException
    {
	Name n = Name.fromString("My.Name.");
	Name m = Name.fromString("M.O.n.");
	
	TestClass tc = new TestClass(n, Type.MX, DClass.IN, 0xB12FL,
				     0x1F2B, "u16 description",
				     m, "name description");

	// canonical
	DNSOutput dout = new DNSOutput();
	tc.rrToWire(dout, null, true);
	byte[] out = dout.toByteArray();
	byte[] exp = new byte[] { 0x1F, 0x2B, 1, 'm', 1, 'o', 1, 'n', 0 };
	assertTrue(Arrays.equals(exp, out));

	// case sensitive
	dout = new DNSOutput();
	tc.rrToWire(dout, null, false);
	out = dout.toByteArray();
	exp = new byte[] { 0x1F, 0x2B, 1, 'M', 1, 'O', 1, 'n', 0 };
	assertTrue(Arrays.equals(exp, out));
    }
}

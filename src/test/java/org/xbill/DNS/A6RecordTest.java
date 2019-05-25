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
package	org.xbill.DNS;

import	java.io.IOException;
import	java.net.InetAddress;
import	java.net.UnknownHostException;
import	java.util.Arrays;
import	junit.framework.TestCase;

public class A6RecordTest extends TestCase
{
    Name m_an, m_an2, m_rn;
    InetAddress m_addr;
    String m_addr_string, m_addr_string_canonical;
    byte[] m_addr_bytes;
    int m_prefix_bits;
    long m_ttl;

    protected void setUp() throws TextParseException,
				  UnknownHostException
    {
	m_an = Name.fromString("My.Absolute.Name.");
	m_an2 = Name.fromString("My.Second.Absolute.Name.");
	m_rn = Name.fromString("My.Relative.Name");
	m_addr_string = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334";
	m_addr_string_canonical = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
	m_addr = InetAddress.getByName(m_addr_string);
	m_addr_bytes = m_addr.getAddress();
	m_ttl = 0x13579;
	m_prefix_bits = 9;
    }

    public void test_ctor_0arg()
    {
	A6Record ar = new A6Record();
	assertNull(ar.getName());
	assertEquals(0, ar.getType());
	assertEquals(0, ar.getDClass());
	assertEquals(0, ar.getTTL());
    }

    public void test_getObject()
    {
	A6Record ar = new A6Record();
	Record r = ar.getObject();
	assertTrue(r instanceof A6Record);
    }

    public void test_ctor_6arg()
    {
	A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, null);
	assertEquals(m_an, ar.getName());
	assertEquals(Type.A6, ar.getType());
	assertEquals(DClass.IN, ar.getDClass());
	assertEquals(m_ttl, ar.getTTL());
	assertEquals(m_prefix_bits, ar.getPrefixBits());
	assertEquals(m_addr, ar.getSuffix());
	assertNull(ar.getPrefix());

	// with the prefix name
	ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
	assertEquals(m_an, ar.getName());
	assertEquals(Type.A6, ar.getType());
	assertEquals(DClass.IN, ar.getDClass());
	assertEquals(m_ttl, ar.getTTL());
	assertEquals(m_prefix_bits, ar.getPrefixBits());
	assertEquals(m_addr, ar.getSuffix());
	assertEquals(m_an2, ar.getPrefix());

	// a relative name
	try {
	    new A6Record(m_rn, DClass.IN, m_ttl, m_prefix_bits, m_addr, null);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}

	// a relative prefix name
	try {
	    new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_rn);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}

	// invalid prefix bits
	try {
	    new A6Record(m_rn, DClass.IN, m_ttl, 0x100, m_addr, null);
	    fail("IllegalArgumentException not thrown");
	}
	catch( RelativeNameException e ){}

	// an IPv4 address
	try {
	    new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits,
			InetAddress.getByName("192.168.0.1"), null);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){}
	catch( UnknownHostException e ){ fail(e.getMessage()); }
    }

    public void test_rrFromWire() throws CloneNotSupportedException,
					 IOException,
					 UnknownHostException
    {
	// record with no prefix
	DNSOutput dout = new DNSOutput();
	dout.writeU8(0);
	dout.writeByteArray(m_addr_bytes);

	DNSInput din = new DNSInput(dout.toByteArray());
	A6Record ar = new A6Record();
	ar.rrFromWire(din);
	assertEquals(0, ar.getPrefixBits());
	assertEquals(m_addr, ar.getSuffix());
	assertNull(ar.getPrefix());

	// record with 9 bit prefix (should result in 15 bytes of the address)
	dout = new DNSOutput();
	dout.writeU8(9);
	dout.writeByteArray(m_addr_bytes, 1, 15);
	dout.writeByteArray(m_an2.toWire());

	din = new DNSInput(dout.toByteArray());
	ar = new A6Record();
	ar.rrFromWire(din);
	assertEquals(9, ar.getPrefixBits());

	byte[] addr_bytes = (byte[])m_addr_bytes.clone();
	addr_bytes[0] = 0;
	InetAddress exp = InetAddress.getByAddress(addr_bytes);
	assertEquals(exp, ar.getSuffix());
	assertEquals(m_an2, ar.getPrefix());
    }

    public void test_rdataFromString() throws CloneNotSupportedException,
					      IOException,
					      UnknownHostException
    {
	// record with no prefix
	Tokenizer t = new Tokenizer("0 " + m_addr_string);
	A6Record ar = new A6Record();
	ar.rdataFromString(t, null);
	assertEquals(0, ar.getPrefixBits());
	assertEquals(m_addr, ar.getSuffix());
	assertNull(ar.getPrefix());

	// record with 9 bit prefix.  In contrast to the rrFromWire method,
	// rdataFromString expects the entire 128 bits to be represented
	// in the string
	t = new Tokenizer("9 " + m_addr_string + " " + m_an2);
	ar = new A6Record();
	ar.rdataFromString(t, null);
	assertEquals(9, ar.getPrefixBits());
	assertEquals(m_addr, ar.getSuffix());
	assertEquals(m_an2, ar.getPrefix());

	// record with invalid prefixBits
	t = new Tokenizer("129");
	ar = new A6Record();
	try {
	    ar.rdataFromString(t, null);
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}

	// record with invalid ipv6 address
	t = new Tokenizer("0 " + m_addr_string.substring(4));
	ar = new A6Record();
	try {
	    ar.rdataFromString(t, null);
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}
    }

    public void test_rrToString()
    {
	A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
	String exp = "" + m_prefix_bits + " " + m_addr_string_canonical + " " + m_an2;
	String out = ar.rrToString();
	assertEquals(exp, out);
    }

    public void test_rrToWire()
    {
	// canonical form
	A6Record ar = new A6Record(m_an, DClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
	DNSOutput dout = new DNSOutput();
	dout.writeU8(m_prefix_bits);
	dout.writeByteArray(m_addr_bytes, 1, 15);
	dout.writeByteArray(m_an2.toWireCanonical());

	byte[] exp = dout.toByteArray();
	
	dout = new DNSOutput();
	ar.rrToWire(dout, null, true);
	
	assertTrue(Arrays.equals(exp, dout.toByteArray()));

	// case sensitiveform
	dout = new DNSOutput();
	dout.writeU8(m_prefix_bits);
	dout.writeByteArray(m_addr_bytes, 1, 15);
	dout.writeByteArray(m_an2.toWire());

	exp = dout.toByteArray();
	
	dout = new DNSOutput();
	ar.rrToWire(dout, null, false);
	assertTrue(Arrays.equals(exp, dout.toByteArray()));
    }
}

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

import	java.net.InetAddress;
import	java.net.UnknownHostException;
import	java.util.Arrays;
import	junit.framework.TestCase;

public class AddressTest extends TestCase
{
    private void assertEquals( byte[] exp, byte[] act )
    {
	assertTrue(Arrays.equals(exp, act));
    }

    private void assertEquals( int[] exp, int[] act )
    {
	assertEquals( exp.length, act.length );
	for( int i=0; i<exp.length; ++i ){
	    assertEquals( "i=" + i, exp[i], act[i] );
	}
    }

    public void test_toByteArray_invalid()
    {
	try {
	    Address.toByteArray("doesn't matter", 3);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_toByteArray_IPv4()
    {
	byte[] exp = new byte[] { (byte)198, (byte)121, (byte)10, (byte)234 };
	byte[] ret = Address.toByteArray("198.121.10.234", Address.IPv4);
	assertEquals(exp, ret);

	exp = new byte[] { 0, 0, 0, 0 };
	ret = Address.toByteArray("0.0.0.0", Address.IPv4);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
	ret = Address.toByteArray("255.255.255.255", Address.IPv4);
    }

    public void test_toByteArray_IPv4_invalid()
    {
	assertNull(Address.toByteArray("A.B.C.D", Address.IPv4));

	assertNull(Address.toByteArray("128...", Address.IPv4));
	assertNull(Address.toByteArray("128.121", Address.IPv4));
	assertNull(Address.toByteArray("128.111.8", Address.IPv4));
	assertNull(Address.toByteArray("128.198.10.", Address.IPv4));

	assertNull(Address.toByteArray("128.121.90..10", Address.IPv4));
	assertNull(Address.toByteArray("128.121..90.10", Address.IPv4));
	assertNull(Address.toByteArray("128..121.90.10", Address.IPv4));
	assertNull(Address.toByteArray(".128.121.90.10", Address.IPv4));

	assertNull(Address.toByteArray("128.121.90.256", Address.IPv4));
	assertNull(Address.toByteArray("128.121.256.10", Address.IPv4));
	assertNull(Address.toByteArray("128.256.90.10", Address.IPv4));
	assertNull(Address.toByteArray("256.121.90.10", Address.IPv4));

	assertNull(Address.toByteArray("128.121.90.-1", Address.IPv4));
	assertNull(Address.toByteArray("128.121.-1.10", Address.IPv4));
	assertNull(Address.toByteArray("128.-1.90.10", Address.IPv4));
	assertNull(Address.toByteArray("-1.121.90.10", Address.IPv4));

	assertNull(Address.toByteArray("120.121.90.10.10", Address.IPv4));

	assertNull(Address.toByteArray("120.121.90.010", Address.IPv4));
	assertNull(Address.toByteArray("120.121.090.10", Address.IPv4));
	assertNull(Address.toByteArray("120.021.90.10", Address.IPv4));
	assertNull(Address.toByteArray("020.121.90.10", Address.IPv4));

	assertNull(Address.toByteArray("1120.121.90.10", Address.IPv4));
	assertNull(Address.toByteArray("120.2121.90.10", Address.IPv4));
	assertNull(Address.toByteArray("120.121.4190.10", Address.IPv4));
	assertNull(Address.toByteArray("120.121.190.1000", Address.IPv4));

	assertNull(Address.toByteArray("", Address.IPv4));
    }

    public void test_toByteArray_IPv6()
    {
	byte[] exp = new byte[] { (byte)32, (byte)1, (byte)13, (byte)184,
				  (byte)133, (byte)163, (byte)8, (byte)211,
				  (byte)19, (byte)25, (byte)138, (byte)46, 
				  (byte)3, (byte)112, (byte)115, (byte)52 };
	byte[] ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:0370:7334", Address.IPv6);
	assertEquals(exp, ret);
	ret = Address.toByteArray("2001:db8:85a3:8d3:1319:8a2e:370:7334", Address.IPv6);
	assertEquals(exp, ret);
	ret = Address.toByteArray("2001:DB8:85A3:8D3:1319:8A2E:370:7334", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0,
			   0, 0, 0, 0, 0, 0, 0, 0 };
	ret = Address.toByteArray("0:0:0:0:0:0:0:0", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
			   (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
			   (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
			   (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
	ret = Address.toByteArray("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)32, (byte)1, (byte)13, (byte)184,
			   (byte)0, (byte)0, (byte)8, (byte)211,
			   (byte)19, (byte)25, (byte)138, (byte)46, 
			   (byte)3, (byte)112, (byte)115, (byte)52 };
	ret = Address.toByteArray("2001:0db8:0000:08d3:1319:8a2e:0370:7334", Address.IPv6);
	assertEquals(exp, ret);

	ret = Address.toByteArray("2001:0db8::08d3:1319:8a2e:0370:7334", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)0, (byte)0, (byte)0, (byte)0,
			   (byte)133, (byte)163, (byte)8, (byte)211,
			   (byte)19, (byte)25, (byte)138, (byte)46, 
			   (byte)3, (byte)112, (byte)115, (byte)52 };
	ret = Address.toByteArray("0000:0000:85a3:08d3:1319:8a2e:0370:7334", Address.IPv6);
	assertEquals(exp, ret);
	ret = Address.toByteArray("::85a3:08d3:1319:8a2e:0370:7334", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)32, (byte)1, (byte)13, (byte)184,
			   (byte)133, (byte)163, (byte)8, (byte)211,
			   (byte)19, (byte)25, (byte)138, (byte)46, 
			   (byte)0, (byte)0, (byte)0, (byte)0 };
	ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:0:0", Address.IPv6);
	assertEquals(exp, ret);

	ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e::", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)32, (byte)1, (byte)13, (byte)184,
			   (byte)0, (byte)0, (byte)0, (byte)0,
			   (byte)0, (byte)0, (byte)0, (byte)0, 
			   (byte)3, (byte)112, (byte)115, (byte)52 };
	ret = Address.toByteArray("2001:0db8:0000:0000:0000:0000:0370:7334", Address.IPv6);
	assertEquals(exp, ret);
	ret = Address.toByteArray("2001:0db8:0:0:0:0:0370:7334", Address.IPv6);
	assertEquals(exp, ret);
	ret = Address.toByteArray("2001:0db8::0:0370:7334", Address.IPv6);
	assertEquals(exp, ret);
	ret = Address.toByteArray("2001:db8::370:7334", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)32, (byte)1, (byte)13, (byte)184,
			   (byte)133, (byte)163, (byte)8, (byte)211,
			   (byte)19, (byte)25, (byte)138, (byte)46, 
			   (byte)0xC0, (byte)0xA8, (byte)0x59, (byte)0x09 };
	ret = Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:192.168.89.9", Address.IPv6);
	assertEquals(exp, ret);

	exp = new byte[] { (byte)0, (byte)0, (byte)0, (byte)0,
			   (byte)0, (byte)0, (byte)0, (byte)0,
			   (byte)0, (byte)0, (byte)0, (byte)0, 
			   (byte)0xC0, (byte)0xA8, (byte)0x59, (byte)0x09 };
	ret = Address.toByteArray("::192.168.89.9", Address.IPv6);
	assertEquals(exp, ret);
    }

    public void test_toByteArray_IPv6_invalid()
    {
	// not enough groups
	assertNull(Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:0370", Address.IPv6));
	// too many groups
	assertNull(Address.toByteArray("2001:0db8:85a3:08d3:1319:8a2e:0370:193A:BCdE", Address.IPv6));
	// invalid letter
	assertNull(Address.toByteArray("2001:0gb8:85a3:08d3:1319:8a2e:0370:9819", Address.IPv6));
	assertNull(Address.toByteArray("lmno:0bb8:85a3:08d3:1319:8a2e:0370:9819", Address.IPv6));
	assertNull(Address.toByteArray("11ab:0ab8:85a3:08d3:1319:8a2e:0370:qrst", Address.IPv6));
	// three consecutive colons
	assertNull(Address.toByteArray("11ab:0ab8:85a3:08d3:::", Address.IPv6));
	// IPv4 in the middle
	assertNull(Address.toByteArray("2001:0ab8:192.168.0.1:1319:8a2e:0370:9819", Address.IPv6));
	// invalid IPv4
	assertNull(Address.toByteArray("2001:0ab8:1212:AbAb:8a2e:345.12.22.1", Address.IPv6));
	// group with too many digits
	assertNull(Address.toByteArray("2001:0ab8:85a3:128d3:1319:8a2e:0370:9819", Address.IPv6));
	
    }

    public void test_toArray()
    {
	int[] exp = new int[] { 1, 2, 3, 4 };
	int[] ret = Address.toArray("1.2.3.4", Address.IPv4);
	assertEquals( exp, ret );

	exp = new int[] { 0, 0, 0, 0 };
	ret = Address.toArray("0.0.0.0", Address.IPv4);
	assertEquals( exp, ret );

	exp = new int[] { 255, 255, 255, 255 };
	ret = Address.toArray("255.255.255.255", Address.IPv4);
	assertEquals( exp, ret );
    }

    public void test_toArray_invalid()
    {
	assertNull(Address.toArray("128.121.1", Address.IPv4));

	assertNull(Address.toArray(""));
    }

    public void test_isDottedQuad()
    {
	assertTrue(Address.isDottedQuad("1.2.3.4"));
	assertFalse(Address.isDottedQuad("256.2.3.4"));
    }

    public void test_toDottedQuad()
    {
	assertEquals("128.176.201.1",
		     Address.toDottedQuad(new byte[] { (byte)128, (byte)176, (byte)201, (byte)1 }));

	assertEquals("200.1.255.128",
		     Address.toDottedQuad(new int[] { 200, 1, 255, 128 }));
    }

    public void test_addressLength()
    {
	assertEquals(4, Address.addressLength(Address.IPv4));
	assertEquals(16, Address.addressLength(Address.IPv6));

	try {
	    Address.addressLength(3);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_getByName() throws UnknownHostException
    {
	InetAddress out = Address.getByName("128.145.198.231");
	assertEquals("128.145.198.231", out.getHostAddress());

	out = Address.getByName("a.root-servers.net");
	assertEquals("198.41.0.4", out.getHostAddress());
    }

    public void test_getByName_invalid() throws UnknownHostException
    {
	try {
	    Address.getByName("example.invalid");
	    fail("UnknownHostException not thrown");
	}
	catch( UnknownHostException e ){
	}
	try {
	    Address.getByName("");
	    fail("UnknownHostException not thrown");
	}
	catch( UnknownHostException e ){
	}
    }

    public void test_getAllByName() throws UnknownHostException
    {
	InetAddress[] out = Address.getAllByName("128.145.198.231");
	assertEquals(1, out.length);
	assertEquals("128.145.198.231", out[0].getHostAddress());

	out = Address.getAllByName("a.root-servers.net");
	assertTrue(out.length == 2);
	assertEquals("198.41.0.4", out[0].getHostAddress());
	assertEquals("2001:503:ba3e:0:0:0:2:30", out[1].getHostAddress());

	out = Address.getAllByName("cnn.com");
	assertTrue(out.length > 1);
	for( int i=0; i<out.length; ++i){
	    assertTrue(out[i].getHostName().endsWith("cnn.com"));
	}
    }

    public void test_getAllByName_invalid() throws UnknownHostException
    {
	try {
	    Address.getAllByName("example.invalid");
	    fail("UnknownHostException not thrown");
	}
	catch( UnknownHostException e ){
	}
	try {
	    Address.getAllByName("");
	    fail("UnknownHostException not thrown");
	}
	catch( UnknownHostException e ){
	}
    }

    public void test_familyOf() throws UnknownHostException
    {
	assertEquals(Address.IPv4, Address.familyOf(InetAddress.getByName("192.168.0.1")));
	assertEquals(Address.IPv6, Address.familyOf(InetAddress.getByName("1:2:3:4:5:6:7:8")));
	try {
	    Address.familyOf(null);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_getHostName() throws UnknownHostException
    {
	String out = Address.getHostName(InetAddress.getByName("198.41.0.4"));
	assertEquals("a.root-servers.net.", out);

	try {
	    Address.getHostName(InetAddress.getByName("192.168.1.1"));
	    fail("UnknownHostException not thrown");
	}
	catch( UnknownHostException e ){
	}
    }
}

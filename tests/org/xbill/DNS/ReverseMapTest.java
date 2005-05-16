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
import	junit.framework.TestCase;

public class ReverseMapTest extends TestCase
{
    public void test_fromAddress_ipv4() throws UnknownHostException,
						    TextParseException
    {
	Name exp = Name.fromString("1.0.168.192.in-addr.arpa.");
	String addr = "192.168.0.1";
	assertEquals(exp, ReverseMap.fromAddress(addr));

	assertEquals(exp, ReverseMap.fromAddress(addr, Address.IPv4));
	assertEquals(exp, ReverseMap.fromAddress(InetAddress.getByName(addr)));
	assertEquals(exp, ReverseMap.fromAddress(new byte[] { (byte)192, (byte)168, (byte)0, (byte)1 }));
	assertEquals(exp, ReverseMap.fromAddress(new int[] { 192, 168, 0, 1 }));
    }

    public void test_fromAddress_ipv6() throws UnknownHostException,
						    TextParseException
    {
	Name exp = Name.fromString("4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa.");
	String addr = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334";
	byte[] dat = new byte[] { (byte)32, (byte)1, (byte)13, (byte)184,
				  (byte)133, (byte)163, (byte)8, (byte)211,
				  (byte)19, (byte)25, (byte)138, (byte)46, 
				  (byte)3, (byte)112, (byte)115, (byte)52 };
	int[] idat = new int[] { 32, 1, 13, 184, 133, 163, 8, 211,
				  19, 25, 138, 46, 3, 112, 115, 52 };
	

	assertEquals(exp, ReverseMap.fromAddress(addr, Address.IPv6));
	assertEquals(exp, ReverseMap.fromAddress(InetAddress.getByName(addr)));
	assertEquals(exp, ReverseMap.fromAddress(dat));
	assertEquals(exp, ReverseMap.fromAddress(idat));
    }

    public void test_fromAddress_invalid()
    {
	try {
	    ReverseMap.fromAddress("A.B.C.D", Address.IPv4);
	    fail("UnknownHostException not thrown");
	}
	catch( UnknownHostException e ){
	}
	try {ReverseMap.fromAddress(new byte [ 0 ] ); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {ReverseMap.fromAddress(new byte [ 3 ] ); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {ReverseMap.fromAddress(new byte [ 5 ] ); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {ReverseMap.fromAddress(new byte [ 15 ] ); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {ReverseMap.fromAddress(new byte [ 17 ] ); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}

	try {
	    int[] dat = new int[] { 0, 1, 2, 256 };
	    ReverseMap.fromAddress(dat);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }
}

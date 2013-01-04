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

public class DNSKEYRecordTest extends TestCase
{
    public void test_ctor_0arg() throws UnknownHostException
    {
	DNSKEYRecord ar = new DNSKEYRecord();
	assertNull(ar.getName());
	assertEquals(0, ar.getType());
	assertEquals(0, ar.getDClass());
	assertEquals(0, ar.getTTL());
	assertEquals(0, ar.getAlgorithm());
	assertEquals(0, ar.getFlags());
	assertEquals(0, ar.getFootprint());
	assertEquals(0, ar.getProtocol());
	assertNull(ar.getKey());
    }

    public void test_getObject()
    {
	DNSKEYRecord ar = new DNSKEYRecord();
	Record r = ar.getObject();
	assertTrue(r instanceof DNSKEYRecord);
    }

    public void test_ctor_7arg() throws TextParseException
    {
	Name n = Name.fromString("My.Absolute.Name.");
	Name r = Name.fromString("My.Relative.Name");
	byte[] key = new byte[] { 0, 1, 3, 5, 7, 9 };

	DNSKEYRecord kr = new DNSKEYRecord(n, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
	assertEquals(n, kr.getName());
	assertEquals(Type.DNSKEY, kr.getType());
	assertEquals(DClass.IN, kr.getDClass());
	assertEquals(0x24AC, kr.getTTL());
	assertEquals(0x9832, kr.getFlags());
	assertEquals(0x12, kr.getProtocol());
	assertEquals(0x67, kr.getAlgorithm());
	assertTrue(Arrays.equals(key, kr.getKey()));

	// a relative name
	try {
	    new DNSKEYRecord(r, DClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
	    fail("RelativeNameException not thrown");
	}
	catch( RelativeNameException e ){}
    }

    public void test_rdataFromString() throws IOException, TextParseException
    {
	// basic
	DNSKEYRecord kr = new DNSKEYRecord();
	Tokenizer st = new Tokenizer(0xABCD + " " + 0x81 + " RSASHA1 AQIDBAUGBwgJ");
	kr.rdataFromString(st, null);
	assertEquals(0xABCD, kr.getFlags());
	assertEquals(0x81, kr.getProtocol());
	assertEquals(DNSSEC.Algorithm.RSASHA1, kr.getAlgorithm());
	assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, kr.getKey()));

	// invalid algorithm
	kr = new DNSKEYRecord();
	st = new Tokenizer(0x1212 + " " + 0xAA + " ZONE AQIDBAUGBwgJ");
	try {
	    kr.rdataFromString(st, null);
	    fail("TextParseException not thrown");
	}
	catch( TextParseException e ){}
    }
}

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

import junit.framework.TestCase;

public class RcodeTest extends TestCase
{
    public void test_string()
    {
	// a regular one
	assertEquals("NXDOMAIN", Rcode.string(Rcode.NXDOMAIN));

	// one with an alias
	assertEquals("NOTIMP", Rcode.string(Rcode.NOTIMP));

	// one that doesn't exist
	assertTrue(Rcode.string(20).startsWith("RESERVED"));

	try {
	    Rcode.string(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	
	//  (max is 0xFFF)
	try {
	    Rcode.string(0x1000);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_TSIGstring()
    {
	// a regular one
	assertEquals("BADSIG", Rcode.TSIGstring(Rcode.BADSIG));

	// one that doesn't exist
	assertTrue(Rcode.TSIGstring(20).startsWith("RESERVED"));

	try {
	    Rcode.TSIGstring(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	
	//  (max is 0xFFFF)
	try {
	    Rcode.string(0x10000);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_value()
    {
	// regular one
	assertEquals(Rcode.FORMERR, Rcode.value("FORMERR"));

	// one with alias
	assertEquals(Rcode.NOTIMP, Rcode.value("NOTIMP"));
	assertEquals(Rcode.NOTIMP, Rcode.value("NOTIMPL"));

	// one thats undefined but within range
	assertEquals(35, Rcode.value("RESERVED35"));

	// one thats undefined but out of range
	assertEquals(-1, Rcode.value("RESERVED" + 0x1000));

	// something that unknown
	assertEquals(-1, Rcode.value("THIS IS DEFINITELY UNKNOWN"));

	// empty string
	assertEquals(-1, Rcode.value(""));
    }
}

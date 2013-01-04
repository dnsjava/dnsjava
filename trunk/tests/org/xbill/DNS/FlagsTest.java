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

public class FlagsTest extends TestCase
{
    public void test_string()
    {
	// a regular one
	assertEquals("aa", Flags.string(Flags.AA));

	// one that doesn't exist
	assertTrue(Flags.string(12).startsWith("flag"));

	try {
	    Flags.string(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	
	//  (max is 0xF)
	try {
	    Flags.string(0x10);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_value()
    {
	// regular one
	assertEquals(Flags.CD, Flags.value("cd"));

	// one thats undefined but within range
	assertEquals(13, Flags.value("FLAG13"));

	// one thats undefined but out of range
	assertEquals(-1, Flags.value("FLAG" + 0x10));

	// something that unknown
	assertEquals(-1, Flags.value("THIS IS DEFINITELY UNKNOWN"));

	// empty string
	assertEquals(-1, Flags.value(""));
    }

    public void test_isFlag()
    {
	try {
	    Flags.isFlag(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	assertTrue(Flags.isFlag(0));
	assertFalse(Flags.isFlag(1)); // opcode
	assertFalse(Flags.isFlag(2));
	assertFalse(Flags.isFlag(3));
	assertFalse(Flags.isFlag(4));
	assertTrue(Flags.isFlag(5));
	assertTrue(Flags.isFlag(6));
	assertTrue(Flags.isFlag(7));
	assertTrue(Flags.isFlag(8));
	assertTrue(Flags.isFlag(9));
	assertTrue(Flags.isFlag(10));
	assertTrue(Flags.isFlag(11));
	assertFalse(Flags.isFlag(12));
	assertFalse(Flags.isFlag(13));
	assertFalse(Flags.isFlag(14));
	assertFalse(Flags.isFlag(14));
	try {
	    Flags.isFlag(16);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }
}

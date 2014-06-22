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

import static org.junit.Assert.*;
import org.junit.Test;

public class ExtendedFlagsTest
{
    @Test
    public void test_string()
    {
	// a regular one
	assertEquals("do", ExtendedFlags.string(ExtendedFlags.DO));

	// one that doesn't exist
	assertTrue(ExtendedFlags.string(1).startsWith("flag"));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void test_string_MinusOne()
    {
	ExtendedFlags.string(-1);
	
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void test_string_MaxValue()
    {
	//  (max is 0xFFFF)
	ExtendedFlags.string(0x10000);
    }

    @Test
    public void test_value()
    {
	// regular one
	assertEquals(ExtendedFlags.DO, ExtendedFlags.value("do"));

	// one thats undefined but within range
	assertEquals(16, ExtendedFlags.value("FLAG16"));

	// one thats undefined but out of range
	assertEquals(-1, ExtendedFlags.value("FLAG" + 0x10000));

	// something that unknown
	assertEquals(-1, ExtendedFlags.value("THIS IS DEFINITELY UNKNOWN"));

	// empty string
	assertEquals(-1, ExtendedFlags.value(""));
    }
}

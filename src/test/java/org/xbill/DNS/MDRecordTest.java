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

import	junit.framework.TestCase;

public class MDRecordTest extends TestCase
{
    public void test_ctor_0arg()
    {
	MDRecord d = new MDRecord();
	assertNull(d.getName());
	assertNull(d.getAdditionalName());
	assertNull(d.getMailAgent());
    }

    public void test_ctor_4arg() throws TextParseException
    {
	Name n = Name.fromString("my.name.");
	Name a = Name.fromString("my.alias.");

	MDRecord d = new MDRecord(n, DClass.IN, 0xABCDEL, a);
	assertEquals(n, d.getName());
	assertEquals(Type.MD, d.getType());
	assertEquals(DClass.IN, d.getDClass());
	assertEquals(0xABCDEL, d.getTTL());
	assertEquals(a, d.getAdditionalName());
	assertEquals(a, d.getMailAgent());
    }

    public void test_getObject()
    {
	MDRecord d = new MDRecord();
	Record r = d.getObject();
	assertTrue(r instanceof MDRecord);
    }
}

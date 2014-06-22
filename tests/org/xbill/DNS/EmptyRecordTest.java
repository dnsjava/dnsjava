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

import static org.junit.Assert.*;
import org.junit.Test;

public class EmptyRecordTest
{
    @Test
    public void test_ctor() throws UnknownHostException
    {
	EmptyRecord ar = new EmptyRecord();
	assertNull(ar.getName());
	assertEquals(0, ar.getType());
	assertEquals(0, ar.getDClass());
	assertEquals(0, ar.getTTL());
    }

    @Test
    public void test_getObject()
    {
	EmptyRecord ar = new EmptyRecord();
	Record r = ar.getObject();
	assertTrue(r instanceof EmptyRecord);
    }

    @Test
    public void test_rrFromWire() throws IOException
    {
	DNSInput i = new DNSInput(new byte[] { 1, 2, 3, 4, 5 });
	i.jump(3);

	EmptyRecord er = new EmptyRecord();
	er.rrFromWire(i);
	assertEquals(3, i.current());
	assertNull(er.getName());
	assertEquals(0, er.getType());
	assertEquals(0, er.getDClass());
	assertEquals(0, er.getTTL());
    }

    @Test
    public void test_rdataFromString() throws IOException
    {
	Tokenizer t = new Tokenizer("these are the tokens");
	EmptyRecord er = new EmptyRecord();
	er.rdataFromString(t, null);
	assertNull(er.getName());
	assertEquals(0, er.getType());
	assertEquals(0, er.getDClass());
	assertEquals(0, er.getTTL());
	
	assertEquals("these", t.getString());
    }

    @Test
    public void test_rrToString()
    {
	EmptyRecord er = new EmptyRecord();
	assertEquals("", er.rrToString());
    }

    @Test
    public void test_rrToWire()
    {
	EmptyRecord er = new EmptyRecord();
	DNSOutput out = new DNSOutput();
	er.rrToWire(out, null, true);
	assertEquals(0, out.toByteArray().length);
    }
}

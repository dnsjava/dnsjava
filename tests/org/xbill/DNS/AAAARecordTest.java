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

import static org.junit.Assert.*;
import	java.io.IOException;
import	java.net.InetAddress;
import	java.net.UnknownHostException;
import	java.util.Arrays;
import org.junit.Before;
import org.junit.Test;

public class AAAARecordTest
{
    Name m_an, m_rn;
    InetAddress m_addr;
    String m_addr_string;
    byte[] m_addr_bytes;
    long m_ttl;
    
    @Before
    public void init() throws TextParseException,
				  UnknownHostException
    {
	m_an = Name.fromString("My.Absolute.Name.");
	m_rn = Name.fromString("My.Relative.Name");
	m_addr_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
	m_addr = InetAddress.getByName(m_addr_string);
	m_addr_bytes = m_addr.getAddress();
	m_ttl = 0x13579;
    }

    @Test
    public void test_ctor_0arg() throws UnknownHostException
    {
	AAAARecord ar = new AAAARecord();
	assertNull(ar.getName());
	assertEquals(0, ar.getType());
	assertEquals(0, ar.getDClass());
	assertEquals(0, ar.getTTL());
	assertNull(ar.getAddress());
    }

    @Test
    public void test_getObject()
    {
	AAAARecord ar = new AAAARecord();
	Record r = ar.getObject();
	assertTrue(r instanceof AAAARecord);
    }

    @Test
    public void test_ctor_4arg() throws UnknownHostException
    {
	AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, m_addr);
	assertEquals(m_an, ar.getName());
	assertEquals(Type.AAAA, ar.getType());
	assertEquals(DClass.IN, ar.getDClass());
	assertEquals(m_ttl, ar.getTTL());
	assertEquals(m_addr, ar.getAddress());
    }
    
    @Test(expected = RelativeNameException.class)
    public void test_ctor_4argRelativeName() 
    {
	// a relative name
	new AAAARecord(m_rn, DClass.IN, m_ttl, m_addr);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void test_ctor_4argIPv4Address() throws UnknownHostException
    {
        // an IPv4 address
	new AAAARecord(m_an, DClass.IN, m_ttl,
			InetAddress.getByName("192.168.0.1"));
    }

    @Test
    public void test_rrFromWire() throws IOException
    {
	DNSInput di = new DNSInput(m_addr_bytes);
	AAAARecord ar = new AAAARecord();

	ar.rrFromWire(di);
	
	assertEquals(m_addr, ar.getAddress());
    }

    @Test
    public void test_rdataFromString() throws IOException
    {
	Tokenizer t = new Tokenizer(m_addr_string);
	AAAARecord ar = new AAAARecord();

	ar.rdataFromString(t, null);

	assertEquals(m_addr, ar.getAddress());
    }
    
    @Test(expected = TextParseException.class)
    public void test_rdataFromStringInvalidAddress() throws IOException
    {
	// invalid address
	Tokenizer t = new Tokenizer("193.160.232.1");
	AAAARecord ar = new AAAARecord();
	ar.rdataFromString(t, null);
    }

    @Test
    public void test_rrToString()
    {
	AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, m_addr);
	assertEquals(m_addr_string, ar.rrToString());
    }

    @Test
    public void test_rrToWire()
    {
	AAAARecord ar = new AAAARecord(m_an, DClass.IN, m_ttl, m_addr);

	// canonical
	DNSOutput dout = new DNSOutput();
	ar.rrToWire(dout, null, true);
	assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()));

	// case sensitive
	dout = new DNSOutput();
	ar.rrToWire(dout, null, false);
	assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()));
    }
}

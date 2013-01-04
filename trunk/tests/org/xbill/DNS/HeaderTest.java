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

import java.io.IOException;
import junit.framework.TestCase;
import org.xbill.DNS.DNSInput;
import org.xbill.DNS.DNSOutput;
import org.xbill.DNS.Header;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Flags;

public class HeaderTest extends TestCase
{
    private Header m_h;

    public void setUp()
    {
	m_h = new Header(0xABCD); // 43981
    }

    public void test_fixture_state()
    {
	assertEquals(0xABCD, m_h.getID());

	boolean[] flags = m_h.getFlags();
	for( int i=0; i<flags.length; ++i){
	    assertFalse(flags[i]);
	}
	assertEquals(0, m_h.getRcode());
	assertEquals(0, m_h.getOpcode());
	assertEquals(0, m_h.getCount(0));
	assertEquals(0, m_h.getCount(1));
	assertEquals(0, m_h.getCount(2));
	assertEquals(0, m_h.getCount(3));
    }

    public void test_ctor_0arg()
    {
	m_h = new Header();
	assertTrue(0 <= m_h.getID() && m_h.getID() < 0xFFFF);

	boolean[] flags = m_h.getFlags();
	for( int i=0; i<flags.length; ++i){
	    assertFalse(flags[i]);
	}
	assertEquals(0, m_h.getRcode());
	assertEquals(0, m_h.getOpcode());
	assertEquals(0, m_h.getCount(0));
	assertEquals(0, m_h.getCount(1));
	assertEquals(0, m_h.getCount(2));
	assertEquals(0, m_h.getCount(3));
    }

    public void test_ctor_DNSInput() throws IOException
    {
	byte[] raw = new byte[] { (byte)0x12, (byte)0xAB, // ID
				  (byte)0x8F, (byte)0xBD, // flags: 1 0001 1 1 1 1 011 1101
				  (byte)0x65, (byte)0x1C, // QDCOUNT
				  (byte)0x10, (byte)0xF0, // ANCOUNT
				  (byte)0x98, (byte)0xBA, // NSCOUNT
				  (byte)0x71, (byte)0x90 }; // ARCOUNT

	m_h = new Header(new DNSInput(raw));

	assertEquals(0x12AB, m_h.getID());

	boolean[] flags = m_h.getFlags();

	assertTrue(flags[0]);

	assertEquals(1, m_h.getOpcode());

	assertTrue(flags[5]);

	assertTrue(flags[6]);

	assertTrue(flags[7]);

	assertTrue(flags[8]);

	assertFalse(flags[9]);
	assertTrue(flags[10]);
	assertTrue(flags[11]);

	assertEquals(0xD, m_h.getRcode());

	assertEquals(0x651C, m_h.getCount(0));
	assertEquals(0x10F0, m_h.getCount(1));
	assertEquals(0x98BA, m_h.getCount(2));
	assertEquals(0x7190, m_h.getCount(3));
    }

    public void test_toWire() throws IOException
    {
	byte[] raw = new byte[] { (byte)0x12, (byte)0xAB, // ID
				  (byte)0x8F, (byte)0xBD, // flags: 1 0001 1 1 1 1 011 1101
				  (byte)0x65, (byte)0x1C, // QDCOUNT
				  (byte)0x10, (byte)0xF0, // ANCOUNT
				  (byte)0x98, (byte)0xBA, // NSCOUNT
				  (byte)0x71, (byte)0x90 }; // ARCOUNT
	
	m_h = new Header(raw);
	
	DNSOutput dout = new DNSOutput();
	m_h.toWire(dout);
	
	byte[] out = dout.toByteArray();

	assertEquals(12, out.length);
	for( int i=0; i<out.length; ++i){
	    assertEquals(raw[i], out[i]);
	}

	m_h.setOpcode(0xA); // 1010
	assertEquals(0xA, m_h.getOpcode());
	m_h.setRcode(0x7);  // 0111

	// flags is now: 1101 0111 1011 0111

	raw[2] = (byte)0xD7;
	raw[3] = (byte)0xB7;

	out = m_h.toWire();
	
	assertEquals(12, out.length);
	for( int i=0; i<out.length; ++i){
	    assertEquals("i=" + i, raw[i], out[i]);
	}
    }

    public void test_flags()
    {
	m_h.setFlag(0);
	m_h.setFlag(5);
	assertTrue(m_h.getFlag(0));
	assertTrue(m_h.getFlags()[0]);
	assertTrue(m_h.getFlag(5));
	assertTrue(m_h.getFlags()[5]);

	m_h.unsetFlag(0);
	assertFalse(m_h.getFlag(0));
	assertFalse(m_h.getFlags()[0]);
	assertTrue(m_h.getFlag(5));
	assertTrue(m_h.getFlags()[5]);

	m_h.unsetFlag(5);
	assertFalse(m_h.getFlag(0));
	assertFalse(m_h.getFlags()[0]);
	assertFalse(m_h.getFlag(5));
	assertFalse(m_h.getFlags()[5]);

	boolean[] flags = m_h.getFlags();
	for( int i=0; i<flags.length; ++i){
	    if( (i > 0 && i < 5) || i > 11 ){
		continue;
	    }
	    assertFalse(flags[i]);
	}
    }

    public void test_flags_invalid()
    {
	try {m_h.setFlag(-1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.setFlag(1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.setFlag(16); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.unsetFlag(-1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.unsetFlag(13); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.unsetFlag(16); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.getFlag(-1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.getFlag(4); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.getFlag(16); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
    }

    public void test_ID()
    {
	assertEquals(0xABCD, m_h.getID());

	m_h = new Header();
	
	int id = m_h.getID();
	assertEquals(id, m_h.getID());
	assertTrue(id >= 0 && id < 0xffff);

	m_h.setID(0xDCBA);
	assertEquals(0xDCBA, m_h.getID());
    }

    public void test_setID_invalid()
    {
	try {
	    m_h.setID(0x10000);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	try {
	    m_h.setID(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_Rcode()
    {
	assertEquals(0, m_h.getRcode());

	m_h.setRcode(0xA); // 1010
	assertEquals(0xA, m_h.getRcode());
	for( int i=0; i<12; ++i){
	    if( ( i > 0 && i < 5 ) || i > 11 ){
		continue;
	    }
	    assertFalse(m_h.getFlag(i));
	}
    }

    public void test_setRcode_invalid()
    {
	try {
	    m_h.setRcode(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	try {
	    m_h.setRcode(0x100);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_Opcode()
    {
	assertEquals(0, m_h.getOpcode());

	m_h.setOpcode(0xE); // 1110
	assertEquals(0xE, m_h.getOpcode());

	assertFalse(m_h.getFlag(0));
	for( int i=5; i<12; ++i){
	    assertFalse(m_h.getFlag(i));
	}
	assertEquals(0, m_h.getRcode());
    }

    public void test_setOpcode_invalid()
    {
	try {
	    m_h.setOpcode(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
	try {
	    m_h.setOpcode(0x100);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){
	}
    }

    public void test_Count()
    {
	m_h.setCount(2, 0x1E);
	assertEquals(0, m_h.getCount(0));
	assertEquals(0, m_h.getCount(1));
	assertEquals(0x1E, m_h.getCount(2));
	assertEquals(0, m_h.getCount(3));

	m_h.incCount(0);
	assertEquals(1, m_h.getCount(0));

	m_h.decCount(2);
	assertEquals(0x1E-1, m_h.getCount(2));
    }

    public void test_setCount_invalid()
    {
	try {m_h.setCount(-1, 0); fail("ArrayIndexOutOfBoundsException not thrown");}
	catch( ArrayIndexOutOfBoundsException e ){}
	try {m_h.setCount(4, 0); fail("ArrayIndexOutOfBoundsException not thrown");}
	catch( ArrayIndexOutOfBoundsException e ){}

	try {m_h.setCount(0, -1); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
	try {m_h.setCount(3, 0x10000); fail("IllegalArgumentException not thrown");}
	catch( IllegalArgumentException e ){}
    }

    public void test_getCount_invalid()
    {
	try {m_h.getCount(-1); fail("ArrayIndexOutOfBoundsException not thrown");}
	catch( ArrayIndexOutOfBoundsException e ){}
	try {m_h.getCount(4); fail("ArrayIndexOutOfBoundsException not thrown");}
	catch( ArrayIndexOutOfBoundsException e ){}
    }

    public void test_incCount_invalid()
    {
	m_h.setCount(1, 0xFFFF);
	try {m_h.incCount(1); fail("IllegalStateException not thrown");}
	catch( IllegalStateException e ){}
    }

    public void test_decCount_invalid()
    {
	m_h.setCount(2, 0);
	try {m_h.decCount(2); fail("IllegalStateException not thrown");}
	catch( IllegalStateException e ){}
    }

    public void test_toString()
    {
	m_h.setOpcode(Opcode.value("STATUS"));
	m_h.setRcode(Rcode.value("NXDOMAIN"));
	m_h.setFlag(0); // qr
	m_h.setFlag(7); // rd
	m_h.setFlag(8); // ra
	m_h.setFlag(11); // cd
	m_h.setCount(1, 0xFF);
	m_h.setCount(2, 0x0A);
	

	String text = m_h.toString();

	assertFalse(text.indexOf("id: 43981") == -1);
	assertFalse(text.indexOf("opcode: STATUS") == -1);
	assertFalse(text.indexOf("status: NXDOMAIN") == -1);
	assertFalse(text.indexOf(" qr ") == -1);
	assertFalse(text.indexOf(" rd ") == -1);
	assertFalse(text.indexOf(" ra ") == -1);
	assertFalse(text.indexOf(" cd ") == -1);
	assertFalse(text.indexOf("qd: 0 ") == -1);
	assertFalse(text.indexOf("an: 255 ") == -1);
	assertFalse(text.indexOf("au: 10 ") == -1);
	assertFalse(text.indexOf("ad: 0 ") == -1);
    }
    
    public void test_clone()
    {
	m_h.setOpcode(Opcode.value("IQUERY"));
	m_h.setRcode(Rcode.value("SERVFAIL"));
	m_h.setFlag(0); // qr
	m_h.setFlag(7); // rd
	m_h.setFlag(8); // ra
	m_h.setFlag(11); // cd
	m_h.setCount(1, 0xFF);
	m_h.setCount(2, 0x0A);

	Header h2 = (Header)m_h.clone();

	assertNotSame(m_h, h2);
	assertEquals(m_h.getID(), h2.getID());
	for( int i=0; i<16; ++i){
	    if( (i>0 && i<5) || i > 11){
		continue;
	    }
	    assertEquals(m_h.getFlag(i), h2.getFlag(i));
	}
	for( int i=0; i<4; ++i){
	    assertEquals(m_h.getCount(i), h2.getCount(i));
	}
    }	
}

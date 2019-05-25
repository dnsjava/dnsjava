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

public class DNSOutputTest extends TestCase
{
    private DNSOutput m_do;

    public void setUp()
    {
	m_do = new DNSOutput( 1 );
    }

    private void assertEquals( byte[] exp, byte[] act )
    {
	assertTrue(java.util.Arrays.equals(exp, act));
    }

    public void test_default_ctor()
    {
	m_do = new DNSOutput();
	assertEquals( 0, m_do.current() );
    }

    public void test_initial_state()
    {
	assertEquals( 0, m_do.current() );
	try {
	    m_do.restore();
	    fail( "IllegalStateException not thrown" );
	}
	catch( IllegalStateException e ){
	    // pass
	}
	try {
	    m_do.jump(1);
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_writeU8_basic()
    {
	m_do.writeU8(1);
	assertEquals( 1, m_do.current() );

	byte[] curr = m_do.toByteArray();
	assertEquals( 1, curr.length );
	assertEquals( 1, curr[0] );
    }

    public void test_writeU8_expand()
    {
	// starts off at 1;
	m_do.writeU8(1);
	m_do.writeU8(2);

	assertEquals( 2, m_do.current() );

	byte[] curr = m_do.toByteArray();
	assertEquals( 2, curr.length );
	assertEquals( 1, curr[0] );
	assertEquals( 2, curr[1] );
    }

    public void test_writeU8_max()
    {
	m_do.writeU8(0xFF);
	byte[] curr = m_do.toByteArray();
	assertEquals( (byte)0xFF, (byte)curr[0] );
    }
    
    public void test_writeU8_toobig()
    {
	try {
	    m_do.writeU8( 0x1FF );
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_writeU16_basic()
    {
	m_do.writeU16(0x100);
	assertEquals( 2, m_do.current() );

	byte[] curr = m_do.toByteArray();
	assertEquals( 2, curr.length );
	assertEquals( 1, curr[0] );
	assertEquals( 0, curr[1] );
    }

    public void test_writeU16_max()
    {
	m_do.writeU16(0xFFFF);
	byte[] curr = m_do.toByteArray();
	assertEquals( (byte)0xFF, (byte)curr[0] );
	assertEquals( (byte)0XFF, (byte)curr[1] );
    }
    
    public void test_writeU16_toobig()
    {
	try {
	    m_do.writeU16( 0x1FFFF );
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_writeU32_basic()
    {
	m_do.writeU32(0x11001011);
	assertEquals( 4, m_do.current() );

	byte[] curr = m_do.toByteArray();
	assertEquals( 4, curr.length );
	assertEquals( 0x11, curr[0] );
	assertEquals( 0x00, curr[1] );
	assertEquals( 0x10, curr[2] );
	assertEquals( 0x11, curr[3] );
    }

    public void test_writeU32_max()
    {
	m_do.writeU32(0xFFFFFFFFL);
	byte[] curr = m_do.toByteArray();
	assertEquals( (byte)0xFF, (byte)curr[0] );
	assertEquals( (byte)0XFF, (byte)curr[1] );
	assertEquals( (byte)0XFF, (byte)curr[2] );
	assertEquals( (byte)0XFF, (byte)curr[3] );
    }
    
    public void test_writeU32_toobig()
    {
	try {
	    m_do.writeU32( 0x1FFFFFFFFL );
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_jump_basic()
    {
	m_do.writeU32(0x11223344L);
	assertEquals( 4, m_do.current() );
	m_do.jump( 2 );
	assertEquals( 2, m_do.current() );
	m_do.writeU8( 0x99 );
	byte[] curr = m_do.toByteArray();
	assertEquals( 3, curr.length );
	assertEquals( 0x11, curr[0] );
	assertEquals( 0x22, curr[1] );
	assertEquals( (byte)0x99, (byte)curr[2] );
	
    }

    public void test_writeByteArray_1arg()
    {
	byte[] in = new byte[] { (byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0x12, (byte)0x34 };
	m_do.writeByteArray( in );
	assertEquals( 5, m_do.current() );
	byte[] curr = m_do.toByteArray();
	assertEquals( in, curr );
    }

    public void test_writeByteArray_3arg()
    {
	byte[] in = new byte[] { (byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0x12, (byte)0x34 };
	m_do.writeByteArray( in, 2, 3 );
	assertEquals( 3, m_do.current() );
	byte[] exp = new byte[] { in[2], in[3], in[4] };
	byte[] curr = m_do.toByteArray();
	assertEquals( exp, curr );
    }

    public void test_writeCountedString_basic()
    {
	byte[] in = new byte[] { 'h', 'e', 'l', 'L', '0' };
	m_do.writeCountedString( in );
	assertEquals( in.length + 1, m_do.current() );
	byte[] curr = m_do.toByteArray();
	byte[] exp = new byte[] { (byte)(in.length), in[0], in[1], in[2], in[3], in[4] };
	assertEquals( exp, curr );
    }

    public void test_writeCountedString_empty()
    {
	byte[] in = new byte[] {};
	m_do.writeCountedString( in );
	assertEquals( in.length + 1, m_do.current() );
	byte[] curr = m_do.toByteArray();
	byte[] exp = new byte[] { (byte)(in.length) };
	assertEquals( exp, curr );
    }

    public void test_writeCountedString_toobig()
    {
	byte[] in = new byte [ 256 ];
	try {
	    m_do.writeCountedString(in);
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_save_restore()
    {
	m_do.writeU32( 0x12345678L );
	assertEquals( 4, m_do.current() );
	m_do.save();
	m_do.writeU16( 0xABCD );
	assertEquals( 6, m_do.current() );
	m_do.restore();
	assertEquals( 4, m_do.current() );
	try {
	    m_do.restore();
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalStateException e ){
	    // pass
	}
    }

}

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

import	java.util.Arrays;
import	junit.framework.TestCase;

public class DNSInputTest extends TestCase
{
    private byte[]	m_raw;
    private DNSInput	m_di;

    private void assertEquals( byte[] exp, byte[] act )
    {
	assertTrue(Arrays.equals(exp, act));
    }

    public void setUp()
    {
	m_raw = new byte[] { 0, 1, 2, 3, 4, 5, (byte)255, (byte)255, (byte)255, (byte)255 };
	m_di = new DNSInput( m_raw );
    }

    public void test_initial_state()
    {
	assertEquals( 0, m_di.current() );
	assertEquals( 10, m_di.remaining() );
    }

    public void test_jump1()
    {
	m_di.jump( 1 );
	assertEquals( 1, m_di.current() );
	assertEquals( 9, m_di.remaining() );
    }

    public void test_jump2()
    {
	m_di.jump( 9 );
	assertEquals( 9, m_di.current() );
	assertEquals( 1, m_di.remaining() );
    }

    public void test_jump_invalid()
    {
	try {
	    m_di.jump( 10 );
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_setActive()
    {
	m_di.setActive( 5 );
	assertEquals( 0, m_di.current() );
	assertEquals( 5, m_di.remaining() );
    }

    public void test_setActive_boundary1()
    {
	m_di.setActive( 10 );
	assertEquals( 0, m_di.current() );
	assertEquals( 10, m_di.remaining() );
    }

    public void test_setActive_boundary2()
    {
	m_di.setActive( 0 );
	assertEquals( 0, m_di.current() );
	assertEquals( 0, m_di.remaining() );
    }

    public void test_setActive_invalid()
    {
	try {
	    m_di.setActive( 11 );
	    fail( "IllegalArgumentException not thrown" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_clearActive()
    {
	// first without setting active:
	m_di.clearActive();
	assertEquals( 0, m_di.current() );
	assertEquals( 10, m_di.remaining() );

	m_di.setActive( 5 );
	m_di.clearActive();
	assertEquals( 0, m_di.current() );
	assertEquals( 10, m_di.remaining() );
    }

    public void test_restore_invalid()
    {
	try {
	    m_di.restore();
	    fail( "IllegalStateException not thrown" );
	}
	catch( IllegalStateException e ){
	    // pass
	}
    }

    public void test_save_restore()
    {
	m_di.jump( 4 );
	assertEquals( 4, m_di.current() );
	assertEquals( 6, m_di.remaining() );
	
	m_di.save();
	m_di.jump( 0 );
	assertEquals( 0, m_di.current() );
	assertEquals( 10, m_di.remaining() );
	
	m_di.restore();
	assertEquals( 4, m_di.current() );
	assertEquals( 6, m_di.remaining() );
    }

    public void test_readU8_basic() throws WireParseException
    {
	int v1 = m_di.readU8();
	assertEquals( 1, m_di.current() );
	assertEquals( 9, m_di.remaining() );
	assertEquals( 0, v1 );
    }

    public void test_readU8_maxval() throws WireParseException
    {
	m_di.jump( 9 );
	int v1 = m_di.readU8();
	assertEquals( 10, m_di.current() );
	assertEquals( 0, m_di.remaining() );
	assertEquals( 255, v1 );

	try {
	    v1 = m_di.readU8();
	    fail( "WireParseException not thrown" );
	}
	catch( WireParseException e ){
	    // pass
	}
    }
    
    public void test_readU16_basic() throws WireParseException
    {
	int v1 = m_di.readU16();
	assertEquals( 2, m_di.current() );
	assertEquals( 8, m_di.remaining() );
	assertEquals( 1, v1 );

	m_di.jump( 1 );
	v1 = m_di.readU16();
	assertEquals( 258, v1 );
    }

    public void test_readU16_maxval() throws WireParseException
    {
	m_di.jump(8);
	int v = m_di.readU16();
	assertEquals( 10, m_di.current() );
	assertEquals( 0, m_di.remaining() );
	assertEquals( 0xFFFF, v );
	
	try {
	    m_di.jump( 9 );
	    m_di.readU16();
	    fail( "WireParseException not thrown" );
	}
	catch( WireParseException e ){
	    // pass 
	}
    }

    public void test_readU32_basic() throws WireParseException
    {
	long v1 = m_di.readU32();
	assertEquals( 4, m_di.current() );
	assertEquals( 6, m_di.remaining() );
	assertEquals( 66051, v1 );
    }

    public void test_readU32_maxval() throws WireParseException
    {
	m_di.jump(6);
	long v = m_di.readU32();
	assertEquals( 10, m_di.current() );
	assertEquals( 0, m_di.remaining() );
	assertEquals( 0xFFFFFFFFL, v );
	
	try {
	    m_di.jump( 7 );
	    m_di.readU32();
	    fail( "WireParseException not thrown" );
	}
	catch( WireParseException e ){
	    // pass 
	}
    }
    
    public void test_readByteArray_0arg() throws WireParseException
    {
	m_di.jump( 1 );
	byte[] out = m_di.readByteArray();
	assertEquals( 10, m_di.current() );
	assertEquals( 0, m_di.remaining() );
	assertEquals( 9, out.length );
	for( int i=0; i<9; ++i ){
	    assertEquals( m_raw[i+1], out[i] );
	}
    }

    public void test_readByteArray_0arg_boundary() throws WireParseException
    {
	m_di.jump(9);
	m_di.readU8();
	byte[] out = m_di.readByteArray();
	assertEquals( 0, out.length );
    }

    public void test_readByteArray_1arg() throws WireParseException
    {
	byte[] out = m_di.readByteArray( 2 );
	assertEquals( 2, m_di.current() );
	assertEquals( 8, m_di.remaining() );
	assertEquals( 2, out.length );
	assertEquals( 0, out[0] );
	assertEquals( 1, out[1] );
    }

    public void test_readByteArray_1arg_boundary() throws WireParseException
    {
	byte[] out = m_di.readByteArray( 10 );
	assertEquals( 10, m_di.current() );
	assertEquals( 0, m_di.remaining() );
	assertEquals( m_raw, out );
    }

    public void test_readByteArray_1arg_invalid()
    {
	try {
	    m_di.readByteArray( 11 );
	    fail( "WireParseException not thrown" );
	}
	catch( WireParseException e ){
	    // pass
	}
    }

    public void test_readByteArray_3arg() throws WireParseException
    {
	byte[] data = new byte [ 5 ];
	m_di.jump(4);
	
	m_di.readByteArray( data, 1, 4 );
	assertEquals( 8, m_di.current() );
	assertEquals( 0, data[0] );
	for( int i=0; i<4; ++i ){
	    assertEquals( m_raw[i+4], data[i+1] );
	}
    }

    public void test_readCountedSting() throws WireParseException
    {
	m_di.jump( 1 );
	byte[] out = m_di.readCountedString();
	assertEquals( 1, out.length );
	assertEquals( 3, m_di.current() );
	assertEquals( out[0], 2 );
    }
}

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
package org.xbill.DNS.utils;

import junit.framework.TestCase;

public class base64Test extends TestCase
{
    public base64Test( String name )
    {
	super(name);
    }

    public void test_toString_empty()
    {
	byte[] data = new byte [ 0 ];
	String out = base64.toString( data );
	assertEquals( "", out );
    }

    public void test_toString_basic1()
    {
	byte[] data = { 0 };
	String out = base64.toString( data );
	assertEquals( "AA==", out );
    }

    public void test_toString_basic2()
    {
	byte[] data = { 0, 0 };
	String out = base64.toString( data );
	assertEquals( "AAA=", out );
    }

    public void test_toString_basic3()
    {
	byte[] data = { 0, 0, 1 };
	String out = base64.toString( data );
	assertEquals( "AAAB", out );
    }

    public void test_toString_basic4()
    {
	byte[] data = { (byte)0xFC, 0, 0 };
	String out = base64.toString( data );
	assertEquals( "/AAA", out );
    }

    public void test_toString_basic5()
    {
	byte[] data = { (byte)0xFF, (byte)0xFF, (byte)0xFF };
	String out = base64.toString( data );
	assertEquals( "////", out );
    }

    public void test_toString_basic6()
    {
	byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	String out = base64.toString( data );
	assertEquals( "AQIDBAUGBwgJ", out );
    }

    public void test_formatString_empty1()
    {
	String out = base64.formatString( new byte [ 0 ], 5, "", false );
	assertEquals( "", out );
    }

    public void test_formatString_shorter()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 13, "", false );
	assertEquals( "AQIDBAUGBwgJ", out );
    }

    public void test_formatString_sameLength()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 12, "", false );
	assertEquals( "AQIDBAUGBwgJ", out );
    }

    public void test_formatString_oneBreak()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 10, "", false );
	assertEquals( "AQIDBAUGBw\ngJ", out );
    }

    public void test_formatString_twoBreaks1()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 5, "", false );
	assertEquals( "AQIDB\nAUGBw\ngJ", out );
    }

    public void test_formatString_twoBreaks2()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 4, "", false );
	assertEquals( "AQID\nBAUG\nBwgJ", out );
    }

    public void test_formatString_shorterWithPrefix()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 13, "!_", false );
	assertEquals( "!_AQIDBAUGBwgJ", out );
    }

    public void test_formatString_sameLengthWithPrefix()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 12, "!_", false );
	assertEquals( "!_AQIDBAUGBwgJ", out );
    }

    public void test_formatString_oneBreakWithPrefix()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 10, "!_", false );
	assertEquals( "!_AQIDBAUGBw\n!_gJ", out );
    }

    public void test_formatString_twoBreaks1WithPrefix()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 5, "!_", false );
	assertEquals( "!_AQIDB\n!_AUGBw\n!_gJ", out );
    }

    public void test_formatString_twoBreaks2WithPrefix()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 4, "!_", false );
	assertEquals( "!_AQID\n!_BAUG\n!_BwgJ", out );
    }

    public void test_formatString_shorterWithPrefixAndClose()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 13, "!_", true );
	assertEquals( "!_AQIDBAUGBwgJ )", out );
    }

    public void test_formatString_sameLengthWithPrefixAndClose()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 12, "!_", true );
	assertEquals( "!_AQIDBAUGBwgJ )", out );
    }

    public void test_formatString_oneBreakWithPrefixAndClose()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 10, "!_", true );
	assertEquals( "!_AQIDBAUGBw\n!_gJ )", out );
    }

    public void test_formatString_twoBreaks1WithPrefixAndClose()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 5, "!_", true );
	assertEquals( "!_AQIDB\n!_AUGBw\n!_gJ )", out );
    }

    public void test_formatString_twoBreaks2WithPrefixAndClose()
    {
	byte[] in = { 1, 2, 3, 4, 5, 6, 7, 8, 9 }; // "AQIDBAUGBwgJ" (12 chars)
	String out = base64.formatString( in, 4, "!_", true );
	assertEquals( "!_AQID\n!_BAUG\n!_BwgJ )", out );
    }

    private void assertEquals( byte[] exp, byte[] act )
    {
	assertEquals( exp.length, act.length );
	for( int i=0; i<exp.length; ++i ){
	    assertEquals( exp[i], act[i] );
	}
    }

    public void test_fromString_empty1()
    {
	byte[] data = new byte [ 0 ];
	byte[] out = base64.fromString( "" );
	assertEquals( new byte [ 0 ], out );
    }

    public void test_fromString_basic1()
    {
	byte[] exp = { 0 };
	byte [] out = base64.fromString( "AA==" );
	assertEquals( exp, out );
    }

    public void test_fromString_basic2()
    {
	byte[] exp = { 0, 0 };
	byte[] out = base64.fromString( "AAA=" );
	assertEquals( exp, out );
    }

    public void test_fromString_basic3()
    {
	byte[] exp = { 0, 0, 1 };
	byte[] out = base64.fromString( "AAAB" );
	assertEquals( exp, out );
    }

    public void test_fromString_basic4()
    {
	byte[] exp = { (byte)0xFC, 0, 0 };
	byte[] out = base64.fromString( "/AAA" );
	assertEquals( exp, out );
    }

    public void test_fromString_basic5()
    {
	byte[] exp = { (byte)0xFF, (byte)0xFF, (byte)0xFF };
	byte[] out = base64.fromString( "////" );
	assertEquals( exp, out );
    }

    public void test_fromString_basic6()
    {
	byte[] exp = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	byte[] out = base64.fromString( "AQIDBAUGBwgJ" );
	assertEquals( exp, out );
    }

    public void test_fromString_invalid1()
    {
	byte[] out = base64.fromString( "AAA" );
	assertNull( out );
    }

    public void test_fromString_invalid2()
    {
	byte[] out = base64.fromString( "AA" );
	assertNull( out );
    }

    public void test_fromString_invalid3()
    {
	byte[] out = base64.fromString( "A" );
	assertNull( out );
    }

    public void test_fromString_invalid4()
    {
	byte[] out = base64.fromString( "BB==" );
	assertNull( out );
    }

    public void test_fromString_invalid5()
    {
	byte[] out = base64.fromString( "BBB=" );
	assertNull( out );
    }

}

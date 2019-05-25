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

public class hexdumpTest extends TestCase
{
    public hexdumpTest( String name )
    {
	super(name);
    }

    /*
     * this seems to be basically a debugging routine, so its most
     * important to check that the values are all rendered correctly,
     * not the formatting.
     */
    
    public void test_shortform()
    {
	byte[] data = new byte[] { 1, 1, 1, 1, 1,
				   2, 2, 2, 2, 2, 
				   2, 2, 2, 2, 2, 
				   2, 2, 2, 2, 2, 
				   2, 2, 2, 2, 2, 
				   2, 2, 2, 2, 2, 
				   2, 2, 2, 2, 2, 
				   2, 2, 2, 2, 2, 
				   3, 3, 3, 3, 3, 3, 3, };
	String desc = "This Is My Description";

	// compare against output from the long form
	String long_out = hexdump.dump( desc, data, 0, data.length );
	String short_out = hexdump.dump( desc, data );

	assertEquals( long_out, short_out );
    }

    public void test_0()
    {
	byte[] data = new byte[] { 1, 0, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t00 \n", out );
    }

    public void test_1()
    {
	byte[] data = new byte[] { 2, 1, 3 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t01 \n", out );
    }

    public void test_2()
    {
	byte[] data = new byte[] { 1, 2, 3 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t02 \n", out );
    }

    public void test_3()
    {
	byte[] data = new byte[] { 1, 3, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t03 \n", out );
    }

    public void test_4()
    {
	byte[] data = new byte[] { 1, 4, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t04 \n", out );
    }

    public void test_5()
    {
	byte[] data = new byte[] { 1, 5, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t05 \n", out );
    }

    public void test_6()
    {
	byte[] data = new byte[] { 1, 6, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t06 \n", out );
    }

    public void test_7()
    {
	byte[] data = new byte[] { 1, 7, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t07 \n", out );
    }

    public void test_8()
    {
	byte[] data = new byte[] { 1, 8, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t08 \n", out );
    }

    public void test_9()
    {
	byte[] data = new byte[] { 1, 9, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t09 \n", out );
    }

    public void test_10()
    {
	byte[] data = new byte[] { 1, 10, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t0A \n", out );
    }

    public void test_11()
    {
	byte[] data = new byte[] { 1, 11, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t0B \n", out );
    }

    public void test_12()
    {
	byte[] data = new byte[] { 1, 12, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t0C \n", out );
    }

    public void test_13()
    {
	byte[] data = new byte[] { 1, 13, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t0D \n", out );
    }

    public void test_14()
    {
	byte[] data = new byte[] { 1, 14, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t0E \n", out );
    }

    public void test_15()
    {
	byte[] data = new byte[] { 1, 15, 2 };
	String out = hexdump.dump( null, data, 1, 1 );
	assertEquals( "1b:\t0F \n", out );
    }

    // strictly for stupid code coverage...a useless test
    public void test_default_constructor()
    {
	new hexdump();
    }
}

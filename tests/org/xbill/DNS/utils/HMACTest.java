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

import	java.security.MessageDigest;
import	java.security.NoSuchAlgorithmException;
import	junit.framework.TestCase;

public class HMACTest extends TestCase
{
    private static class test_data
    {
	public byte[] key;
	public byte[] data;
	public byte[] digest;
    }

    private static test_data[] tests;

    static {
	// These test cases come directly from RFC 2202 (for MD5)

	tests = new test_data[7];

	for( int i=0; i<tests.length; ++i){
	    tests[i] = new test_data();
	}

	// test_case =     1
	tests[0].key =		base16.fromString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	tests[0].data =		"Hi There".getBytes();
	tests[0].digest =	base16.fromString("9294727a3638bb1c13f48ef8158bfc9d");

	// test_case =     2
	tests[1].key =		"Jefe".getBytes();
	tests[1].data =		"what do ya want for nothing?".getBytes();
	tests[1].digest =	base16.fromString("750c783e6ab0b503eaa86e310a5db738");
	
	// test_case =     3
	tests[2].key =          base16.fromString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	tests[2].data =		new byte[ 50 ]; // 0xdd repeated 50 times
	for( int i=0; i<tests[2].data.length; ++i){
	    tests[2].data[i] = (byte)0xdd;
	}
	tests[2].digest =       base16.fromString("56be34521d144c88dbb8c733f0e8b3f6");

	// test_case =     4
	tests[3].key =          base16.fromString("0102030405060708090a0b0c0d0e0f10111213141516171819");
	tests[3].data =         new byte[ 50 ]; // 0xcd repeated 50 times;
	for( int i=0; i<tests[3].data.length; ++i){
	    tests[3].data[i] = (byte)0xcd;
	}
	tests[3].digest =       base16.fromString("697eaf0aca3a3aea3a75164746ffaa79");
	    
	// test_case =     5
	tests[4].key =		base16.fromString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
	tests[4].data =         "Test With Truncation".getBytes();
	tests[4].digest =       base16.fromString("56461ef2342edc00f9bab995690efd4c");

	// test_case =     6
	tests[5].key =		 new byte[ 80 ]; // 0xaa repeated 80 times;
	for( int i=0; i<tests[5].key.length; ++i){
	    tests[5].key[i] = (byte)0xaa;
	}
	tests[5].data =          "Test Using Larger Than Block-Size Key - Hash Key First".getBytes();
	tests[5].digest =        base16.fromString("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");

	// test_case =     7
	tests[6].key =           new byte [ 80 ]; // 0xaa repeated 80 times;
	for( int i=0; i<tests[6].key.length; ++i){
	    tests[6].key[i] = (byte)0xaa;
	}
	tests[6].data =          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
	tests[6].digest =        base16.fromString("6f630fad67cda0ee1fb1f562db3aa53e");
    }

    public HMACTest( String name )
    {
	super(name);
    }


    private void do_test(int i, HMAC h) throws CloneNotSupportedException
    {
	h.update(tests[i].data, 0, tests[i].data.length);
	byte[] out = h.sign();
	
	assertEquals("test=" + i, tests[i].digest.length, out.length);
	for( int j=0; j<out.length; ++j){
	    assertEquals("test=" + i, tests[i].digest[j], out[j]);
	}
	
	// clear and do it again to make sure verify() agrees
	h.clear();
	h.update(tests[i].data);
	assertTrue(h.verify(tests[i].digest));
	
	// clear and do it again to make sure verify() 
	h.clear();
	h.update(tests[i].data, 0, tests[i].data.length);
	byte[] tmp = (byte[])tests[i].digest.clone();
	tmp[tmp.length/2] = (byte)0xAB;
	assertFalse(h.verify(tmp));
    }

    public void test_ctor_digest_key() throws NoSuchAlgorithmException,
					      CloneNotSupportedException
    {
	for( int i=0; i<tests.length; ++i){
	    MessageDigest md = MessageDigest.getInstance("md5");
	    HMAC h = new HMAC(md, tests[i].key);
	    do_test(i, h);
	}
    }

    public void test_ctor_digestName_key() throws NoSuchAlgorithmException,
					      CloneNotSupportedException
    {
	for( int i=0; i<tests.length; ++i){
	    HMAC h = new HMAC("md5", tests[i].key);
	    do_test(i, h);
	}
    }

    public void test_ctor_digestName_key_invalid()
    {
	try {
	    new HMAC("no name", new byte[ 0 ]);
	    fail("IllegalArgumentException not thrown");
	}
	catch( IllegalArgumentException e ){}
    }
}

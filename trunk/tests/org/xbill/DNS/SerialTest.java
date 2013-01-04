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

import	junit.framework.TestCase;

public class SerialTest extends TestCase
{
    public void test_compare_NegativeArg1()
    {
	long arg1 = -1;
	long arg2 = 1;
	try {
	    Serial.compare( arg1, arg2 );
	    fail( "compare accepted negative argument 1" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_compare_OOBArg1()
    {
	long arg1 = 0xFFFFFFFFL + 1;
	long arg2 = 1;
	try {
	    Serial.compare( arg1, arg2 );
	    fail( "compare accepted out-of-bounds argument 1" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_compare_NegativeArg2()
    {
	long arg1 = 1;
	long arg2 = -1;
	try {
	    Serial.compare( arg1, arg2 );
	    fail( "compare accepted negative argument 2" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_compare_OOBArg2()
    {
	long arg1 = 1;
	long arg2 = 0xFFFFFFFFL + 1;
	try {
	    Serial.compare( arg1, arg2 );
	    fail( "compare accepted out-of-bounds argument 1" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_compare_Arg1Greater()
    {
	long arg1 = 10;
	long arg2 = 9;
	int ret = Serial.compare( arg1, arg2 );
	assertTrue( ret > 0 );
    }

    public void test_compare_Arg2Greater()
    {
	long arg1 = 9;
	long arg2 = 10;
	int ret = Serial.compare( arg1, arg2 );
	assertTrue( ret < 0 );
    }

    public void test_compare_ArgsEqual()
    {
	long arg1 = 10;
	long arg2 = 10;
	int ret = Serial.compare( arg1, arg2 );
	assertEquals( ret, 0 );
    }

    public void test_compare_boundary()
    {
	long arg1 = 0xFFFFFFFFL;
	long arg2 = 0;
	int ret = Serial.compare( arg1, arg2 );
	assertEquals( -1, ret );
	ret = Serial.compare( arg2, arg1 );
	assertEquals( 1, ret );
    }

    public void test_increment_NegativeArg()
    {
	long arg = -1;
	try {
	    Serial.increment( arg );
	    fail( "increment accepted negative argument" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_increment_OOBArg()
    {
	long arg = 0xFFFFFFFFL + 1;
	try {
	    Serial.increment( arg );
	    fail( "increment accepted out-of-bounds argument" );
	}
	catch( IllegalArgumentException e ){
	    // pass
	}
    }

    public void test_increment_reset()
    {
	long arg = 0xFFFFFFFFL;
	long ret = Serial.increment( arg );
	assertEquals( 0, ret );
    }

    public void test_increment_normal()
    {
	long arg = 10;
	long ret = Serial.increment( arg );
	assertEquals( arg+1, ret );
    }
}

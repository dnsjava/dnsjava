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

public class TTLTest extends TestCase
{
    private final long S = 1;
    private final long M = 60*S;
    private final long H = 60*M;
    private final long D = 24*H;
    private final long W = 7*D;

    public void test_parseTTL()
    {
	assertEquals(9876, TTL.parseTTL("9876"));

	assertEquals(0, TTL.parseTTL("0S"));
	assertEquals(0, TTL.parseTTL("0M"));
	assertEquals(0, TTL.parseTTL("0H"));
	assertEquals(0, TTL.parseTTL("0D"));
	assertEquals(0, TTL.parseTTL("0W"));

	assertEquals(S, TTL.parseTTL("1s"));
	assertEquals(M, TTL.parseTTL("1m"));
	assertEquals(H, TTL.parseTTL("1h"));
	assertEquals(D, TTL.parseTTL("1d"));
	assertEquals(W, TTL.parseTTL("1w"));

	assertEquals(98*S, TTL.parseTTL("98S"));
	assertEquals(76*M, TTL.parseTTL("76M"));
	assertEquals(54*H, TTL.parseTTL("54H"));
	assertEquals(32*D, TTL.parseTTL("32D"));
	assertEquals(10*W, TTL.parseTTL("10W"));

	assertEquals(98*S+11*M+1234*H+2*D+W, TTL.parseTTL("98S11M1234H2D01W"));
    }

    public void test_parseTTL_invalid()
    {
	try {TTL.parseTTL(null); fail("NumberFormatException not throw");}
	catch( NumberFormatException e ){}

	try {TTL.parseTTL(""); fail("NumberFormatException not throw");}
	catch( NumberFormatException e ){}

	try {TTL.parseTTL("S"); fail("NumberFormatException not throw");}
	catch( NumberFormatException e ){}

	try {TTL.parseTTL("10S4B"); fail("NumberFormatException not throw");}
	catch( NumberFormatException e ){}

	try {TTL.parseTTL("1S"+0xFFFFFFFFL+"S"); fail("NumberFormatException not throw");}
	catch( NumberFormatException e ){}

	try {TTL.parseTTL(""+0x100000000L); fail("NumberFormatException not throw");}
	catch( NumberFormatException e ){}
    }

    public void test_format()
    {
	assertEquals("0S", TTL.format(0));
	assertEquals("1S", TTL.format(1));
	assertEquals("59S", TTL.format(59));
	assertEquals("1M", TTL.format(60));
	assertEquals("59M", TTL.format(59*M));
	assertEquals("1M33S", TTL.format(M+33));
	assertEquals("59M59S", TTL.format(59*M+59*S));
	assertEquals("1H", TTL.format(H));
	assertEquals("10H1M21S", TTL.format(10*H+M+21));
	assertEquals("23H59M59S", TTL.format(23*H+59*M+59));
	assertEquals("1D", TTL.format(D));
	assertEquals("4D18H45M30S", TTL.format(4*D+18*H+45*M+30));
	assertEquals("6D23H59M59S", TTL.format(6*D+23*H+59*M+59));
	assertEquals("1W", TTL.format(W));
	assertEquals("10W4D1H21M29S", TTL.format(10*W+4*D+H+21*M+29));
	assertEquals("3550W5D3H14M7S", TTL.format(0x7FFFFFFFL));
    }

    public void test_format_invalid()
    {
	try {TTL.format(-1); fail("InvalidTTLException not thrown");
	} catch( InvalidTTLException e ){}

	try {TTL.format(0x100000000L); fail("InvalidTTLException not thrown");
	} catch( InvalidTTLException e ){}
    }
}

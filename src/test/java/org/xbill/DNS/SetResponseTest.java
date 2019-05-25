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

import	java.net.InetAddress;
import	java.net.UnknownHostException;
import	java.util.Arrays;
import	junit.framework.TestCase;

public class SetResponseTest extends TestCase
{
    public void test_ctor_1arg()
    {
	final int[] types = new int[] { SetResponse.UNKNOWN,
					SetResponse.NXDOMAIN,
					SetResponse.NXRRSET,
					SetResponse.DELEGATION,
					SetResponse.CNAME,
					SetResponse.DNAME,
					SetResponse.SUCCESSFUL };

	for( int i=0; i<types.length; ++i){
	    SetResponse sr = new SetResponse(types[i]);
	    assertNull(sr.getNS());
	    assertEquals(types[i] == SetResponse.UNKNOWN, sr.isUnknown());
	    assertEquals(types[i] == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
	    assertEquals(types[i] == SetResponse.NXRRSET, sr.isNXRRSET());
	    assertEquals(types[i] == SetResponse.DELEGATION, sr.isDelegation());
	    assertEquals(types[i] == SetResponse.CNAME, sr.isCNAME());
	    assertEquals(types[i] == SetResponse.DNAME, sr.isDNAME());
	    assertEquals(types[i] == SetResponse.SUCCESSFUL, sr.isSuccessful());
	}
    }

    public void test_ctor_1arg_toosmall()
    {
	try {
	    new SetResponse(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch(IllegalArgumentException a){}
    }

    public void test_ctor_1arg_toobig()
    {
	try {
	    new SetResponse(7);
	    fail("IllegalArgumentException not thrown");
	}
	catch(IllegalArgumentException a){}
    }

    public void test_ctor_2arg()
    {
	final int[] types = new int[] { SetResponse.UNKNOWN,
					SetResponse.NXDOMAIN,
					SetResponse.NXRRSET,
					SetResponse.DELEGATION,
					SetResponse.CNAME,
					SetResponse.DNAME,
					SetResponse.SUCCESSFUL };

	for( int i=0; i<types.length; ++i){
	    RRset rs = new RRset();
	    SetResponse sr = new SetResponse(types[i], rs);
	    assertSame(rs, sr.getNS());
	    assertEquals(types[i] == SetResponse.UNKNOWN, sr.isUnknown());
	    assertEquals(types[i] == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
	    assertEquals(types[i] == SetResponse.NXRRSET, sr.isNXRRSET());
	    assertEquals(types[i] == SetResponse.DELEGATION, sr.isDelegation());
	    assertEquals(types[i] == SetResponse.CNAME, sr.isCNAME());
	    assertEquals(types[i] == SetResponse.DNAME, sr.isDNAME());
	    assertEquals(types[i] == SetResponse.SUCCESSFUL, sr.isSuccessful());
	}
    }

    public void test_ctor_2arg_toosmall()
    {
	try {
	    new SetResponse(-1, new RRset());
	    fail("IllegalArgumentException not thrown");
	}
	catch(IllegalArgumentException a){}
    }

    public void test_ctor_2arg_toobig()
    {
	try {
	    new SetResponse(7, new RRset());
	    fail("IllegalArgumentException not thrown");
	}
	catch(IllegalArgumentException a){}
    }

    public void test_ofType_basic()
    {
	final int[] types = new int[] { SetResponse.DELEGATION,
					SetResponse.CNAME,
					SetResponse.DNAME,
					SetResponse.SUCCESSFUL };

	for(int i=0; i<types.length; ++i){
	    SetResponse sr = SetResponse.ofType(types[i]);
	    assertNull(sr.getNS());
	    assertEquals(types[i] == SetResponse.UNKNOWN, sr.isUnknown());
	    assertEquals(types[i] == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
	    assertEquals(types[i] == SetResponse.NXRRSET, sr.isNXRRSET());
	    assertEquals(types[i] == SetResponse.DELEGATION, sr.isDelegation());
	    assertEquals(types[i] == SetResponse.CNAME, sr.isCNAME());
	    assertEquals(types[i] == SetResponse.DNAME, sr.isDNAME());
	    assertEquals(types[i] == SetResponse.SUCCESSFUL, sr.isSuccessful());

	    SetResponse sr2 = SetResponse.ofType(types[i]);
	    assertNotSame(sr, sr2);
	}
    }

    public void test_ofType_singleton()
    {
	final int[] types = new int[] { SetResponse.UNKNOWN,
					SetResponse.NXDOMAIN,
					SetResponse.NXRRSET };

	for(int i=0; i<types.length; ++i){
	    SetResponse sr = SetResponse.ofType(types[i]);
	    assertNull(sr.getNS());
	    assertEquals(types[i] == SetResponse.UNKNOWN, sr.isUnknown());
	    assertEquals(types[i] == SetResponse.NXDOMAIN, sr.isNXDOMAIN());
	    assertEquals(types[i] == SetResponse.NXRRSET, sr.isNXRRSET());
	    assertEquals(types[i] == SetResponse.DELEGATION, sr.isDelegation());
	    assertEquals(types[i] == SetResponse.CNAME, sr.isCNAME());
	    assertEquals(types[i] == SetResponse.DNAME, sr.isDNAME());
	    assertEquals(types[i] == SetResponse.SUCCESSFUL, sr.isSuccessful());

	    SetResponse sr2 = SetResponse.ofType(types[i]);
	    assertSame(sr, sr2);
	}
    }

    public void test_ofType_toosmall()
    {
	try {
	    SetResponse.ofType(-1);
	    fail("IllegalArgumentException not thrown");
	}
	catch(IllegalArgumentException e ){}
    }

    public void test_ofType_toobig()
    {
	try {
	    SetResponse.ofType(7);
	    fail("IllegalArgumentException not thrown");
	}
	catch(IllegalArgumentException e ){}
    }

    public void test_addRRset() throws TextParseException, UnknownHostException
    {
	RRset rrs = new RRset();
	rrs.addRR(new ARecord(Name.fromString("The.Name."),
			      DClass.IN,
			      0xABCD,
			      InetAddress.getByName("192.168.0.1")));
	rrs.addRR(new ARecord(Name.fromString("The.Name."),
			      DClass.IN,
			      0xABCD,
			      InetAddress.getByName("192.168.0.2")));
	SetResponse sr = new SetResponse(SetResponse.SUCCESSFUL);
	sr.addRRset(rrs);

	RRset[] exp = new RRset[] { rrs };
	assertTrue(Arrays.equals(exp, sr.answers()));
    }

    public void test_addRRset_multiple() throws TextParseException, UnknownHostException
    {
	RRset rrs = new RRset();
	rrs.addRR(new ARecord(Name.fromString("The.Name."),
			      DClass.IN,
			      0xABCD,
			      InetAddress.getByName("192.168.0.1")));
	rrs.addRR(new ARecord(Name.fromString("The.Name."),
			      DClass.IN,
			      0xABCD,
			      InetAddress.getByName("192.168.0.2")));

	RRset rrs2 = new RRset();
	rrs2.addRR(new ARecord(Name.fromString("The.Other.Name."),
			      DClass.IN,
			      0xABCE,
			      InetAddress.getByName("192.168.1.1")));
	rrs2.addRR(new ARecord(Name.fromString("The.Other.Name."),
			      DClass.IN,
			      0xABCE,
			      InetAddress.getByName("192.168.1.2")));

	SetResponse sr = new SetResponse(SetResponse.SUCCESSFUL);
	sr.addRRset(rrs);
	sr.addRRset(rrs2);

	RRset[] exp = new RRset[] { rrs, rrs2 };
	assertTrue(Arrays.equals(exp, sr.answers()));
    }

    public void test_answers_nonSUCCESSFUL()
    {
	SetResponse sr = new SetResponse(SetResponse.UNKNOWN, new RRset());
	assertNull(sr.answers());
    }

    public void test_getCNAME() throws TextParseException, UnknownHostException
    {
	RRset rrs = new RRset();
	CNAMERecord cr = new CNAMERecord(Name.fromString("The.Name."),
					 DClass.IN,
					 0xABCD,
					 Name.fromString("The.Alias."));
	rrs.addRR(cr);
	SetResponse sr = new SetResponse(SetResponse.CNAME, rrs);
	assertEquals(cr, sr.getCNAME());
    }

    public void test_getDNAME() throws TextParseException, UnknownHostException
    {
	RRset rrs = new RRset();
	DNAMERecord dr = new DNAMERecord(Name.fromString("The.Name."),
					 DClass.IN,
					 0xABCD,
					 Name.fromString("The.Alias."));
	rrs.addRR(dr);
	SetResponse sr = new SetResponse(SetResponse.DNAME, rrs);
	assertEquals(dr, sr.getDNAME());
    }

    public void test_toString() throws TextParseException, UnknownHostException
    {
	final int[] types = new int[] { SetResponse.UNKNOWN,
					SetResponse.NXDOMAIN,
					SetResponse.NXRRSET,
					SetResponse.DELEGATION,
					SetResponse.CNAME,
					SetResponse.DNAME,
					SetResponse.SUCCESSFUL };
	RRset rrs = new RRset();
	rrs.addRR(new ARecord(Name.fromString("The.Name."),
			      DClass.IN,
			      0xABCD,
			      InetAddress.getByName("192.168.0.1")));

	final String[] labels = new String[] { "unknown",
					       "NXDOMAIN",
					       "NXRRSET",
					       "delegation: " + rrs,
					       "CNAME: " + rrs,
					       "DNAME: " + rrs,
					       "successful" };

	for( int i=0; i<types.length; ++i){
	    SetResponse sr = new SetResponse(types[i], rrs);
	    assertEquals(labels[i], sr.toString());
	}
    }
}

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

import	java.io.IOException;
import	java.util.Arrays;
import	junit.framework.Test;
import	junit.framework.TestCase;
import	junit.framework.TestSuite;

public class GPOSRecordTest extends TestCase
{
    public void test_ctor_0arg()
    {
	GPOSRecord gr = new GPOSRecord();
	assertNull(gr.getName());
	assertEquals(0, gr.getType());
	assertEquals(0, gr.getDClass());
	assertEquals(0, gr.getTTL());
    }
    
    public void test_getObject()
    {
	GPOSRecord gr = new GPOSRecord();
	Record r = gr.getObject();
	assertTrue(r instanceof GPOSRecord);
    }

    public static class Test_Ctor_6arg_doubles extends TestCase
    {
	private Name	m_n;
	private long	m_ttl;
	private double	m_lat, m_long, m_alt;

	protected void setUp() throws TextParseException
	{
	    m_n = Name.fromString("The.Name.");
	    m_ttl = 0xABCDL;
	    m_lat = -10.43;
	    m_long = 76.12;
	    m_alt = 100.101;
	}
	
	public void test_basic() throws TextParseException
	{
	    GPOSRecord gr = new GPOSRecord(m_n, DClass.IN, m_ttl,
					   m_long, m_lat, m_alt);
	    assertEquals(m_n, gr.getName());
	    assertEquals(DClass.IN, gr.getDClass());
	    assertEquals(Type.GPOS, gr.getType());
	    assertEquals(m_ttl, gr.getTTL());
	    assertEquals(new Double(m_long), new Double(gr.getLongitude()));
	    assertEquals(new Double(m_lat), new Double(gr.getLatitude()));
	    assertEquals(new Double(m_alt), new Double(gr.getAltitude()));
	    assertEquals(new Double(m_long).toString(), gr.getLongitudeString());
	    assertEquals(new Double(m_lat).toString(), gr.getLatitudeString());
	    assertEquals(new Double(m_alt).toString(), gr.getAltitudeString());
	}

	public void test_toosmall_longitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       -90.001, m_lat, m_alt);
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_toobig_longitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       90.001, m_lat, m_alt);
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_toosmall_latitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       m_long, -180.001, m_alt);
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_toobig_latitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       m_long, 180.001, m_alt);
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_invalid_string()
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       new Double(m_long).toString(),
			       "120.\\00ABC", new Double(m_alt).toString());
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}
    }

    public static class Test_Ctor_6arg_Strings extends TestCase
    {
	private Name	m_n;
	private long	m_ttl;
	private double	m_lat, m_long, m_alt;

	protected void setUp() throws TextParseException
	{
	    m_n = Name.fromString("The.Name.");
	    m_ttl = 0xABCDL;
	    m_lat = -10.43;
	    m_long = 76.12;
	    m_alt = 100.101;
	}
	
	public void test_basic() throws TextParseException
	{
	    GPOSRecord gr = new GPOSRecord(m_n, DClass.IN, m_ttl,
					   new Double(m_long).toString(),
					   new Double(m_lat).toString(),
					   new Double(m_alt).toString());
	    assertEquals(m_n, gr.getName());
	    assertEquals(DClass.IN, gr.getDClass());
	    assertEquals(Type.GPOS, gr.getType());
	    assertEquals(m_ttl, gr.getTTL());
	    assertEquals(new Double(m_long), new Double(gr.getLongitude()));
	    assertEquals(new Double(m_lat), new Double(gr.getLatitude()));
	    assertEquals(new Double(m_alt), new Double(gr.getAltitude()));
	    assertEquals(new Double(m_long).toString(), gr.getLongitudeString());
	    assertEquals(new Double(m_lat).toString(), gr.getLatitudeString());
	    assertEquals(new Double(m_alt).toString(), gr.getAltitudeString());
	}

	public void test_toosmall_longitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       "-90.001", new Double(m_lat).toString(),
			       new Double(m_alt).toString());
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_toobig_longitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       "90.001", new Double(m_lat).toString(),
			       new Double(m_alt).toString());
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_toosmall_latitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       new Double(m_long).toString(), "-180.001",
			       new Double(m_alt).toString());
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}

	public void test_toobig_latitude() throws TextParseException
	{
	    try {
		new GPOSRecord(m_n, DClass.IN, m_ttl,
			       new Double(m_long).toString(), "180.001", new Double(m_alt).toString());
		fail("IllegalArgumentException not thrown");
	    }
	    catch(IllegalArgumentException e){}
	}
    }

    public static class Test_rrFromWire extends TestCase
    {
	public void test_basic() throws IOException
	{
	    byte[] raw = new byte[] { 5, '-', '8', '.', '1', '2',
				      6, '1', '2', '3', '.', '0', '7',
				      3, '0', '.', '0' };
	    DNSInput in = new DNSInput(raw);
	    
	    GPOSRecord gr = new GPOSRecord();
	    gr.rrFromWire(in);
	    assertEquals(new Double(-8.12), new Double(gr.getLongitude()));
	    assertEquals(new Double(123.07), new Double(gr.getLatitude()));
	    assertEquals(new Double(0.0), new Double(gr.getAltitude()));
	}
	
	public void test_longitude_toosmall() throws IOException
	{
	    byte[] raw = new byte[] { 5, '-', '9', '5', '.', '0',
				      6, '1', '2', '3', '.', '0', '7',
				      3, '0', '.', '0' };
	    DNSInput in = new DNSInput(raw);
	    
	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rrFromWire(in);
		fail("WireParseException not thrown");
	    }
	    catch(WireParseException e){}
	}

	public void test_longitude_toobig() throws IOException
	{
	    byte[] raw = new byte[] { 5, '1', '8', '5', '.', '0',
				      6, '1', '2', '3', '.', '0', '7',
				      3, '0', '.', '0' };
	    DNSInput in = new DNSInput(raw);

	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rrFromWire(in);
		fail("WireParseException not thrown");
	    }
	    catch(WireParseException e){}
	}

	public void test_latitude_toosmall() throws IOException
	{
	    byte[] raw = new byte[] { 5, '-', '8', '5', '.', '0',
				      6, '-', '1', '9', '0', '.', '0',
				      3, '0', '.', '0' };
	    DNSInput in = new DNSInput(raw);

	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rrFromWire(in);
		fail("WireParseException not thrown");
	    }
	    catch(WireParseException e){}
	}

	public void test_latitude_toobig() throws IOException
	{
	    byte[] raw = new byte[] { 5, '-', '8', '5', '.', '0',
				      6, '2', '1', '9', '0', '.', '0',
				      3, '0', '.', '0' };
	    DNSInput in = new DNSInput(raw);

	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rrFromWire(in);
		fail("WireParseException not thrown");
	    }
	    catch(WireParseException e){}
	}
    }

    public static class Test_rdataFromString extends TestCase
    {
	public void test_basic() throws IOException
	{
	    Tokenizer t = new Tokenizer("10.45 171.121212 1010787");
	    
	    GPOSRecord gr = new GPOSRecord();
	    gr.rdataFromString(t, null);
	    assertEquals(new Double(10.45), new Double(gr.getLongitude()));
	    assertEquals(new Double(171.121212), new Double(gr.getLatitude()));
	    assertEquals(new Double(1010787), new Double(gr.getAltitude()));
	}

	public void test_longitude_toosmall() throws IOException
	{
	    Tokenizer t = new Tokenizer("-100.390 171.121212 1010787");
	    
	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rdataFromString(t, null);
		fail("IOException not thrown");
	    }
	    catch(IOException e){}
	}

	public void test_longitude_toobig() throws IOException
	{
	    Tokenizer t = new Tokenizer("90.00001 171.121212 1010787");
	    
	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rdataFromString(t, null);
		fail("IOException not thrown");
	    }
	    catch(IOException e){}
	}

	public void test_latitude_toosmall() throws IOException
	{
	    Tokenizer t = new Tokenizer("0.0 -180.01 1010787");
	    
	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rdataFromString(t, null);
		fail("IOException not thrown");
	    }
	    catch(IOException e){}
	}

	public void test_latitude_toobig() throws IOException
	{
	    Tokenizer t = new Tokenizer("0.0 180.01 1010787");
	    
	    GPOSRecord gr = new GPOSRecord();
	    try {
		gr.rdataFromString(t, null);
		fail("IOException not thrown");
	    }
	    catch(IOException e){}
	}

	public void test_invalid_string() throws IOException
	{
	    Tokenizer t = new Tokenizer("1.0 2.0 \\435");
	    try {
		GPOSRecord gr = new GPOSRecord();
		gr.rdataFromString(t, null);
	    }
	    catch(TextParseException e){}}
    }

    public void test_rrToString() throws TextParseException
    {
	String exp = "\"10.45\" \"171.121212\" \"1010787.0\"";
	    
	GPOSRecord gr = new GPOSRecord(Name.fromString("The.Name."), DClass.IN, 0x123,
				       10.45, 171.121212, 1010787);
	assertEquals(exp, gr.rrToString());
    }

    public void test_rrToWire() throws TextParseException
    {
	GPOSRecord gr = new GPOSRecord(Name.fromString("The.Name."), DClass.IN, 0x123,
				       -10.45, 120.0, 111.0);

	byte[] exp = new byte[] { 6, '-', '1', '0', '.', '4', '5',
				  5, '1', '2', '0', '.', '0',
				  5, '1', '1', '1', '.', '0' };
	
	DNSOutput out = new DNSOutput();
	gr.rrToWire(out, null, true);

	byte[] bar = out.toByteArray();

	assertEquals(exp.length, bar.length);
	for( int i=0; i<exp.length; ++i){
	    assertEquals("i=" + i, exp[i], bar[i]);
	}
    }

    public static Test suite()
    {
	TestSuite s = new TestSuite();
	s.addTestSuite(Test_Ctor_6arg_doubles.class);
	s.addTestSuite(Test_Ctor_6arg_Strings.class);
	s.addTestSuite(Test_rrFromWire.class);
	s.addTestSuite(Test_rdataFromString.class);
	s.addTestSuite(GPOSRecordTest.class);
	return s;
    }
}

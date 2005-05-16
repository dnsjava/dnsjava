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

import	java.io.IOException;
import	java.net.InetAddress;
import	java.net.UnknownHostException;
import	java.util.Arrays;
import	java.util.ArrayList;
import	java.util.List;
import	junit.framework.Test;
import	junit.framework.TestCase;
import	junit.framework.TestSuite;
import	org.xbill.DNS.APLRecord.Element;

public class APLRecordTest
{
    public static class Test_Element_init extends TestCase
    {
	InetAddress m_addr4;
	InetAddress m_addr6;

	protected void setUp() throws TextParseException,
				      UnknownHostException
	{
	    m_addr4 = InetAddress.getByName("193.160.232.5");
	    m_addr6 = InetAddress.getByName("2001:db8:85a3:8d3:1319:8a2e:370:7334");
	}
	
	public void test_valid_IPv4()
	{
	    Element el = new Element(true, m_addr4, 16);
	    assertEquals(Address.IPv4, el.family);
	    assertEquals(true, el.negative);
	    assertEquals(m_addr4, el.address);
	    assertEquals(16, el.prefixLength);
	}
	
	public void test_invalid_IPv4()
	{
	    try {
		new Element(true, m_addr4, 33);
		fail("IllegalArgumentException not thrown");
	    }
	    catch( IllegalArgumentException e ){}
	}
	
	public void test_valid_IPv6()
	{
	    Element el = new Element(false, m_addr6, 74);
	    assertEquals(Address.IPv6, el.family);
	    assertEquals(false, el.negative);
	    assertEquals(m_addr6, el.address);
	    assertEquals(74, el.prefixLength);
	}
	
	public void test_invalid_IPv6()
	{
	    try {
		new Element(true, m_addr6, 129);
		fail("IllegalArgumentException not thrown");
	    }
	    catch( IllegalArgumentException e ){}
	}
    }

    public static class Test_init extends TestCase
    {
	Name m_an, m_rn;
	long m_ttl;
	ArrayList m_elements;
	InetAddress m_addr4;
	String m_addr4_string;
	byte[] m_addr4_bytes;
	InetAddress m_addr6;
	String m_addr6_string;
	byte[] m_addr6_bytes;

	protected void setUp() throws TextParseException,
				      UnknownHostException
	{
	    m_an = Name.fromString("My.Absolute.Name.");
	    m_rn = Name.fromString("My.Relative.Name");
	    m_ttl = 0x13579;
	    m_addr4_string = "193.160.232.5";
	    m_addr4 = InetAddress.getByName(m_addr4_string);
	    m_addr4_bytes = m_addr4.getAddress();
	    
	    m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
	    m_addr6 = InetAddress.getByName(m_addr6_string);
	    m_addr6_bytes = m_addr6.getAddress();
	    
	    m_elements = new ArrayList(2);
	    Element e = new Element(true, m_addr4, 12);
	    m_elements.add(e);
	    
	    e = new Element(false, m_addr6, 64);
	    m_elements.add(e);
	}
	
	public void test_0arg() throws UnknownHostException
	{
	    APLRecord ar = new APLRecord();
	    assertNull(ar.getName());
	    assertEquals(0, ar.getType());
	    assertEquals(0, ar.getDClass());
	    assertEquals(0, ar.getTTL());
	    assertNull(ar.getElements());
	}

	public void test_getObject()
	{
	    APLRecord ar = new APLRecord();
	    Record r = ar.getObject();
	    assertTrue(r instanceof APLRecord);
	}

	public void test_4arg_basic()
	{
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, m_elements);
	    assertEquals(m_an, ar.getName());
	    assertEquals(Type.APL, ar.getType());
	    assertEquals(DClass.IN, ar.getDClass());
	    assertEquals(m_ttl, ar.getTTL());
	    assertEquals(m_elements, ar.getElements());
	}
	
	public void test_4arg_empty_elements()
	{
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, new ArrayList());
	    assertEquals(new ArrayList(), ar.getElements());
	}
	
	public void test_4arg_relative_name()
	{
	    try {
		new APLRecord(m_rn, DClass.IN, m_ttl, m_elements);
		fail("RelativeNameException not thrown");
	    }
	    catch( RelativeNameException e ){}
	}
	
	public void test_4arg_invalid_elements()
	{
	    m_elements = new ArrayList();
	    m_elements.add(new Object());
	    try {
		new APLRecord(m_an, DClass.IN, m_ttl, m_elements);
		fail("IllegalArgumentException not thrown");
	    }
	    catch( IllegalArgumentException e ){}
	}
    }

    public static class Test_rrFromWire extends TestCase
    {
	InetAddress m_addr4;
	byte[] m_addr4_bytes;
	InetAddress m_addr6;
	byte[] m_addr6_bytes;
	
	protected void setUp() throws TextParseException,
				      UnknownHostException
	{
	    m_addr4 = InetAddress.getByName("193.160.232.5");
	    m_addr4_bytes = m_addr4.getAddress();
	    
	    m_addr6 = InetAddress.getByName("2001:db8:85a3:8d3:1319:8a2e:370:7334");
	    m_addr6_bytes = m_addr6.getAddress();
	}
	
	public void test_validIPv4() throws IOException
	{
	    byte[] raw = new byte[] { 0, 1, 8, (byte)0x84, 
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2], m_addr4_bytes[3] };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    ar.rrFromWire(di);
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(true, m_addr4, 8));
	    assertEquals(exp, ar.getElements());
	}
	
	public void test_validIPv4_short_address() throws IOException
	{
	    byte[] raw = new byte[] { 0, 1, 20, (byte)0x83, 
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2] };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    ar.rrFromWire(di);
	    
	    InetAddress a = InetAddress.getByName("193.160.232.0");
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(true, a, 20));
	    assertEquals(exp, ar.getElements());
	}
	
	public void test_invalid_IPv4_prefix() throws IOException
	{
	    byte[] raw = new byte[] { 0, 1, 33, (byte)0x84, 
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2], m_addr4_bytes[3] };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    try {
		ar.rrFromWire(di);
		fail("WireParseException not thrown");
	    }
	    catch( WireParseException e ){}
	}
	
	public void test_invalid_IPv4_length() throws IOException
	{
	    byte[] raw = new byte[] { 0, 1, 8, (byte)0x85, 
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2], m_addr4_bytes[3], 10 };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    try {
		ar.rrFromWire(di);
		fail("WireParseException not thrown");
	    }
	    catch( WireParseException e ){}
	}
	
	public void test_multiple_validIPv4() throws IOException
	{
	    byte[] raw = new byte[] { 0, 1, 8, (byte)0x84, 
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2], m_addr4_bytes[3],
				      0, 1, 30, (byte)0x4,
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2], m_addr4_bytes[3],
	    };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    ar.rrFromWire(di);
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(true, m_addr4, 8));
	    exp.add(new Element(false, m_addr4, 30));
	    assertEquals(exp, ar.getElements());
	}
	
	public void test_validIPv6() throws IOException
	{
	    byte[] raw = new byte[] { 0, 2, (byte)115, (byte)0x10, 
				      m_addr6_bytes[0], m_addr6_bytes[1],
				      m_addr6_bytes[2], m_addr6_bytes[3],
				      m_addr6_bytes[4], m_addr6_bytes[5],
				      m_addr6_bytes[6], m_addr6_bytes[7],
				      m_addr6_bytes[8], m_addr6_bytes[9],
				      m_addr6_bytes[10], m_addr6_bytes[11],
				      m_addr6_bytes[12], m_addr6_bytes[13],
				      m_addr6_bytes[14], m_addr6_bytes[15] };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    ar.rrFromWire(di);
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(false, m_addr6, 115));
	    assertEquals(exp, ar.getElements());
	}

	public void test_valid_nonIP() throws IOException
	{
	    byte[] raw = new byte[] { 0, 3, (byte)130, (byte)0x85, 
				      1, 2, 3, 4, 5 };
	    
	    DNSInput di = new DNSInput(raw);
	    APLRecord ar = new APLRecord();
	    ar.rrFromWire(di);
	    
	    List l = ar.getElements();
	    assertEquals(1, l.size());
	    
	    Element el = (Element)l.get(0);
	    assertEquals(3, el.family);
	    assertEquals(true, el.negative);
	    assertEquals(130, el.prefixLength);
	    assertTrue(Arrays.equals(new byte[] { 1, 2, 3, 4, 5 },
				     (byte[])el.address));
	}
    }

    public static class Test_rdataFromString extends TestCase
    {
	InetAddress m_addr4;
	String m_addr4_string;
	byte[] m_addr4_bytes;
	InetAddress m_addr6;
	String m_addr6_string;
	byte[] m_addr6_bytes;

	protected void setUp() throws TextParseException,
				      UnknownHostException
	{
	    m_addr4_string = "193.160.232.5";
	    m_addr4 = InetAddress.getByName(m_addr4_string);
	    m_addr4_bytes = m_addr4.getAddress();
	    
	    m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
	    m_addr6 = InetAddress.getByName(m_addr6_string);
	    m_addr6_bytes = m_addr6.getAddress();
	}

	public void test_validIPv4() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:" + m_addr4_string + "/11\n");
	    APLRecord ar = new APLRecord();
	    ar.rdataFromString(t, null);
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(false, m_addr4, 11));
	    
	    assertEquals(exp, ar.getElements());
	    
	    // make sure extra token is put back
	    assertEquals(Tokenizer.EOL, t.get().type);
	}
	
	public void test_valid_multi() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:" + m_addr4_string + "/11 !2:" + m_addr6_string + "/100");
	    APLRecord ar = new APLRecord();
	    ar.rdataFromString(t, null);
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(false, m_addr4, 11));
	    exp.add(new Element(true, m_addr6, 100));
	    
	    assertEquals(exp, ar.getElements());
	}
	
	public void test_validIPv6() throws IOException
	{
	    Tokenizer t = new Tokenizer("!2:" + m_addr6_string + "/36\n");
	    APLRecord ar = new APLRecord();
	    ar.rdataFromString(t, null);
	    
	    ArrayList exp = new ArrayList();
	    exp.add(new Element(true, m_addr6, 36));
	    
	    assertEquals(exp, ar.getElements());
	    
	    // make sure extra token is put back
	    assertEquals(Tokenizer.EOL, t.get().type);
	}
	
	public void test_no_colon() throws IOException
	{
	    Tokenizer t = new Tokenizer("!1192.68.0.1/20");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_colon_and_slash_swapped() throws IOException
	{
	    Tokenizer t = new Tokenizer("!1/192.68.0.1:20");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_no_slash() throws IOException
	{
	    Tokenizer t = new Tokenizer("!1:192.68.0.1|20");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_empty_family() throws IOException
	{
	    Tokenizer t = new Tokenizer("!:192.68.0.1/20");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_malformed_family() throws IOException
	{
	    Tokenizer t = new Tokenizer("family:192.68.0.1/20");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_invalid_family() throws IOException
	{
	    Tokenizer t = new Tokenizer("3:192.68.0.1/20");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_empty_prefix() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:192.68.0.1/");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}

	public void test_malformed_prefix() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:192.68.0.1/prefix");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_invalid_prefix() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:192.68.0.1/33");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_empty_address() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:/33");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
	
	public void test_malformed_address() throws IOException
	{
	    Tokenizer t = new Tokenizer("1:A.B.C.D/33");
	    APLRecord ar = new APLRecord();
	    try {
		ar.rdataFromString(t, null);
		fail("TextParseException not thrown");
	    }
	    catch( TextParseException e ){}
	}
    }

    public static class Test_rrToString extends TestCase
    {
	Name m_an, m_rn;
	long m_ttl;
	ArrayList m_elements;
	InetAddress m_addr4;
	String m_addr4_string;
	byte[] m_addr4_bytes;
	InetAddress m_addr6;
	String m_addr6_string;
	byte[] m_addr6_bytes;

	protected void setUp() throws TextParseException,
				      UnknownHostException
	{
	    m_an = Name.fromString("My.Absolute.Name.");
	    m_rn = Name.fromString("My.Relative.Name");
	    m_ttl = 0x13579;
	    m_addr4_string = "193.160.232.5";
	    m_addr4 = InetAddress.getByName(m_addr4_string);
	    m_addr4_bytes = m_addr4.getAddress();
	    
	    m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
	    m_addr6 = InetAddress.getByName(m_addr6_string);
	    m_addr6_bytes = m_addr6.getAddress();
	    
	    m_elements = new ArrayList(2);
	    Element e = new Element(true, m_addr4, 12);
	    m_elements.add(e);
	    
	    e = new Element(false, m_addr6, 64);
	    m_elements.add(e);
	}
	
	public void test()
	{
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, m_elements);
	    assertEquals("!1:" + m_addr4_string + "/12 2:" + m_addr6_string + "/64",
			 ar.rrToString());
	}
    }

    public static class Test_rrToWire extends TestCase
    {
	Name m_an, m_rn;
	long m_ttl;
	ArrayList m_elements;
	InetAddress m_addr4;
	String m_addr4_string;
	byte[] m_addr4_bytes;
	InetAddress m_addr6;
	String m_addr6_string;
	byte[] m_addr6_bytes;

	protected void setUp() throws TextParseException,
				      UnknownHostException
	{
	    m_an = Name.fromString("My.Absolute.Name.");
	    m_rn = Name.fromString("My.Relative.Name");
	    m_ttl = 0x13579;
	    m_addr4_string = "193.160.232.5";
	    m_addr4 = InetAddress.getByName(m_addr4_string);
	    m_addr4_bytes = m_addr4.getAddress();
	    
	    m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
	    m_addr6 = InetAddress.getByName(m_addr6_string);
	    m_addr6_bytes = m_addr6.getAddress();
	    
	    m_elements = new ArrayList(2);
	    Element e = new Element(true, m_addr4, 12);
	    m_elements.add(e);
	    
	    e = new Element(false, m_addr6, 64);
	    m_elements.add(e);
	}
	
	public void test_empty()
	{
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, new ArrayList());
	    DNSOutput dout = new DNSOutput();
	    
	    ar.rrToWire(dout, null, true);
	    assertTrue(Arrays.equals(new byte[0], dout.toByteArray()));
	}
	
	public void test_basic()
	{
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, m_elements);
	    
	    byte[] exp = new byte[] { 0, 1, 12, (byte)0x84, 
				      m_addr4_bytes[0], m_addr4_bytes[1],
				      m_addr4_bytes[2], m_addr4_bytes[3],
				      0, 2, 64, 0x10,
				      m_addr6_bytes[0], m_addr6_bytes[1],
				      m_addr6_bytes[2], m_addr6_bytes[3],
				      m_addr6_bytes[4], m_addr6_bytes[5],
				      m_addr6_bytes[6], m_addr6_bytes[7],
				      m_addr6_bytes[8], m_addr6_bytes[9],
				      m_addr6_bytes[10], m_addr6_bytes[11],
				      m_addr6_bytes[12], m_addr6_bytes[13],
				      m_addr6_bytes[14], m_addr6_bytes[15] };
	    
	    DNSOutput dout = new DNSOutput();
	    
	    ar.rrToWire(dout, null, true);
	    assertTrue(Arrays.equals(exp, dout.toByteArray()));
	}
	
	public void test_non_IP() throws IOException
	{
	    byte[] exp = new byte[] { 0, 3, (byte)130, (byte)0x85, 
				      1, 2, 3, 4, 5 };
	    
	    DNSInput di = new DNSInput(exp);
	    APLRecord ar = new APLRecord();
	    ar.rrFromWire(di);
	    
	    DNSOutput dout = new DNSOutput();
	    
	    ar.rrToWire(dout, null, true);
	    assertTrue(Arrays.equals(exp, dout.toByteArray()));
	}
	
	public void test_address_with_embedded_zero() throws UnknownHostException
	{
	    InetAddress a = InetAddress.getByName("232.0.11.1");
	    ArrayList elements = new ArrayList();
	    elements.add(new Element(true, a, 31));
	    
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, elements);
	    
	    byte[] exp = new byte[] { 0, 1, 31, (byte)0x84, (byte)232, 0, 11, 1 };
	    
	    DNSOutput dout = new DNSOutput();
	    
	    ar.rrToWire(dout, null, true);
	    assertTrue(Arrays.equals(exp, dout.toByteArray()));
	}
	
	public void test_short_address() throws UnknownHostException
	{
	    InetAddress a = InetAddress.getByName("232.0.11.0");
	    ArrayList elements = new ArrayList();
	    elements.add(new Element(true, a, 31));
	    
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, elements);
	    
	    byte[] exp = new byte[] { 0, 1, 31, (byte)0x83, (byte)232, 0, 11  };
	    
	    DNSOutput dout = new DNSOutput();
	    
	    ar.rrToWire(dout, null, true);
	    assertTrue(Arrays.equals(exp, dout.toByteArray()));
	}
	
	public void test_wildcard_address() throws UnknownHostException
	{
	    InetAddress a = InetAddress.getByName("0.0.0.0");
	    ArrayList elements = new ArrayList();
	    elements.add(new Element(true, a, 31));
	    
	    APLRecord ar = new APLRecord(m_an, DClass.IN, m_ttl, elements);
	    
	    byte[] exp = new byte[] { 0, 1, 31, (byte)0x80 };
	    
	    DNSOutput dout = new DNSOutput();
	    
	    ar.rrToWire(dout, null, true);
	    assertTrue(Arrays.equals(exp, dout.toByteArray()));
	}
    }

    public static Test suite()
    {
	TestSuite s = new TestSuite();
	s.addTestSuite(Test_Element_init.class);
	s.addTestSuite(Test_init.class);
	s.addTestSuite(Test_rrFromWire.class);
	s.addTestSuite(Test_rdataFromString.class);
	s.addTestSuite(Test_rrToString.class);
	s.addTestSuite(Test_rrToWire.class);
	return s;
    }
}

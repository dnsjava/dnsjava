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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SOARecordTest
{
    private final static Random m_random = new Random();

    private static long randomU16()
    {
	return m_random.nextLong() >>> 48;
    }

    private static long randomU32()
    {
	return m_random.nextLong() >>> 32;
    }

    static class Test_init
    {
	private Name m_an, m_rn, m_host, m_admin;
	private long m_ttl, m_serial, m_refresh, m_retry, m_expire, m_minimum;

   @BeforeEach
   void setUp() throws TextParseException {
	    m_an = Name.fromString("My.Absolute.Name.");
	    m_rn = Name.fromString("My.Relative.Name");
	    m_host = Name.fromString("My.Host.Name.");
	    m_admin = Name.fromString("My.Administrative.Name.");
	    m_ttl = randomU16();
	    m_serial = randomU32();
	    m_refresh = randomU32();
	    m_retry = randomU32();
	    m_expire = randomU32();
	    m_minimum = randomU32();
	}
	
    @Test
    void test_0arg() {
	    SOARecord ar = new SOARecord();
	    assertNull(ar.getName());
	    assertEquals(0, ar.getType());
	    assertEquals(0, ar.getDClass());
	    assertEquals(0, ar.getTTL());
	    assertNull(ar.getHost());
	    assertNull(ar.getAdmin());
	    assertEquals(0, ar.getSerial());
	    assertEquals(0, ar.getRefresh());
	    assertEquals(0, ar.getRetry());
	    assertEquals(0, ar.getExpire());
	    assertEquals(0, ar.getMinimum());
	}
	
    @Test
    void test_getObject()
	{
	    SOARecord ar = new SOARecord();
	    Record r = ar.getObject();
	    assertTrue(r instanceof SOARecord);
	}
	
    @Test
    void test_10arg()
	{
	    SOARecord ar = new SOARecord(m_an, DClass.IN, m_ttl,
					 m_host, m_admin, m_serial, m_refresh,
					 m_retry, m_expire, m_minimum);
	    assertEquals(m_an, ar.getName());
	    assertEquals(Type.SOA, ar.getType());
	    assertEquals(DClass.IN, ar.getDClass());
	    assertEquals(m_ttl, ar.getTTL());
	    assertEquals(m_host, ar.getHost());
	    assertEquals(m_admin, ar.getAdmin());
	    assertEquals(m_serial, ar.getSerial());
	    assertEquals(m_refresh, ar.getRefresh());
	    assertEquals(m_retry, ar.getRetry());
	    assertEquals(m_expire, ar.getExpire());
	    assertEquals(m_minimum, ar.getMinimum());
	}
	
    @Test
    void test_10arg_relative_name()
	{
	    assertThrows(RelativeNameException.class, () -> new SOARecord(m_rn, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_relative_host()
	{
	    assertThrows(RelativeNameException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_rn, m_admin, m_serial, m_refresh,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_relative_admin()
	{
	    assertThrows(RelativeNameException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_rn, m_serial, m_refresh,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_negative_serial()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, -1, m_refresh,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_toobig_serial()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, 0x100000000L, m_refresh,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_negative_refresh()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, -1,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_toobig_refresh()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, 0x100000000L,
			      m_retry, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_negative_retry()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      -1, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_toobig_retry()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      0x100000000L, m_expire, m_minimum));
	}
	
    @Test
    void test_10arg_negative_expire()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      m_retry, -1, m_minimum));
	}
	
    @Test
    void test_10arg_toobig_expire()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      m_retry, 0x100000000L, m_minimum));
	}
	
    @Test
    void test_10arg_negative_minimun()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      m_retry, m_expire, -1));
	}
	
    @Test
    void test_10arg_toobig_minimum()
	{
	    assertThrows(IllegalArgumentException.class, () -> new SOARecord(m_an, DClass.IN, m_ttl,
			      m_host, m_admin, m_serial, m_refresh,
			      m_retry, m_expire, 0x100000000L));
	}
    }

    static class Test_rrFromWire
    {
	private Name m_host, m_admin;
	private long m_serial, m_refresh, m_retry, m_expire, m_minimum;

   @BeforeEach
   void setUp() throws TextParseException {
	    m_host = Name.fromString("M.h.N.");
	    m_admin = Name.fromString("M.a.n.");
	    m_serial = 0xABCDEF12L;
	    m_refresh = 0xCDEF1234L;
	    m_retry = 0xEF123456L;
	    m_expire = 0x12345678L;
	    m_minimum = 0x3456789AL;
	}
	
    @Test
    void test() throws IOException
	{
	    byte[] raw = new byte[] {
		1, 'm', 1, 'h', 1, 'n', 0, // host
		1, 'm', 1, 'a', 1, 'n', 0, // admin
		(byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0x12,	   // serial
		(byte)0xCD, (byte)0xEF, (byte)0x12, (byte)0x34,	   // refresh
		(byte)0xEF, (byte)0x12, (byte)0x34, (byte)0x56,	   // retry
		(byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,	   // expire
		(byte)0x34, (byte)0x56, (byte)0x78, (byte)0x9A };  // minimum

	    DNSInput di = new DNSInput(raw);
	    SOARecord ar = new SOARecord();
	    
	    ar.rrFromWire(di);
	    
	    assertEquals(m_host, ar.getHost());
	    assertEquals(m_admin, ar.getAdmin());
	    assertEquals(m_serial, ar.getSerial());
	    assertEquals(m_refresh, ar.getRefresh());
	    assertEquals(m_retry, ar.getRetry());
	    assertEquals(m_expire, ar.getExpire());
	    assertEquals(m_minimum, ar.getMinimum());
	}
    }

    static class Test_rdataFromString
    {
	private Name m_host, m_admin, m_origin;
	private long m_serial, m_refresh, m_retry, m_expire, m_minimum;

   @BeforeEach
   void setUp() throws TextParseException {
	    m_origin = Name.fromString("O.");
	    m_host = Name.fromString("M.h", m_origin);
	    m_admin = Name.fromString("M.a.n.");
	    m_serial = 0xABCDEF12L;
	    m_refresh = 0xCDEF1234L;
	    m_retry = 0xEF123456L;
	    m_expire = 0x12345678L;
	    m_minimum = 0x3456789AL;
	}
	
    @Test
    void test_valid() throws IOException
	{
	    Tokenizer t = new Tokenizer("M.h " + m_admin + " " +
					m_serial + " " +
					m_refresh + " " +
					m_retry + " " +
					m_expire + " " +
					m_minimum);
	    SOARecord ar = new SOARecord();
	    
	    ar.rdataFromString(t, m_origin);
	    
	    assertEquals(m_host, ar.getHost());
	    assertEquals(m_admin, ar.getAdmin());
	    assertEquals(m_serial, ar.getSerial());
	    assertEquals(m_refresh, ar.getRefresh());
	    assertEquals(m_retry, ar.getRetry());
	    assertEquals(m_expire, ar.getExpire());
	    assertEquals(m_minimum, ar.getMinimum());
	}

    @Test
    void test_relative_name() throws IOException
	{
	    Tokenizer t = new Tokenizer("M.h " + m_admin + " " +
					m_serial + " " +
					m_refresh + " " +
					m_retry + " " +
					m_expire + " " +
					m_minimum);
	    SOARecord ar = new SOARecord();
	    
	    assertThrows(RelativeNameException.class, () -> ar.rdataFromString(t, null));
	}
    }

    static class Test_rrToString
    {
	private Name m_an, m_host, m_admin;
	private long m_ttl, m_serial, m_refresh, m_retry, m_expire, m_minimum;

   @BeforeEach
   void setUp() throws TextParseException
	{
	    m_an = Name.fromString("My.absolute.name.");
	    m_ttl = 0x13A8;
	    m_host = Name.fromString("M.h.N.");
	    m_admin = Name.fromString("M.a.n.");
	    m_serial = 0xABCDEF12L;
	    m_refresh = 0xCDEF1234L;
	    m_retry = 0xEF123456L;
	    m_expire = 0x12345678L;
	    m_minimum = 0x3456789AL;
	}

    @Test
    void test_singleLine()
	{
	    SOARecord ar = new SOARecord(m_an, DClass.IN, m_ttl,
					 m_host, m_admin, m_serial, m_refresh,
					 m_retry, m_expire, m_minimum);
	    String exp = m_host + " " + m_admin + " " + m_serial + " " +
		m_refresh + " " + m_retry + " " + m_expire + " " + m_minimum;

	    String out = ar.rrToString();
	    
	    assertEquals(exp, out);
	}

    @Test
    void test_multiLine()
	{
	    SOARecord ar = new SOARecord(m_an, DClass.IN, m_ttl,
					 m_host, m_admin, m_serial, m_refresh,
					 m_retry, m_expire, m_minimum);
	    String re = "^.*\\(\\n" +
		"\\s*" + m_serial + "\\s*;\\s*serial\\n" + // serial
		"\\s*" + m_refresh + "\\s*;\\s*refresh\\n" + // refresh
		"\\s*" + m_retry + "\\s*;\\s*retry\\n" + // retry
		"\\s*" + m_expire + "\\s*;\\s*expire\\n" + // expire
		"\\s*" + m_minimum + "\\s*\\)\\s*;\\s*minimum$"; // minimum

	    Options.set("multiline");
	    String out = ar.rrToString();
	    Options.unset("multiline");

	    assertTrue(out.matches(re));
	}
    }

    static class Test_rrToWire
    {
	private Name m_an, m_host, m_admin;
	private long m_ttl, m_serial, m_refresh, m_retry, m_expire, m_minimum;

   @BeforeEach
   void setUp() throws TextParseException
	{
	    m_an = Name.fromString("My.Abs.Name.");
	    m_ttl = 0x13A8;
	    m_host = Name.fromString("M.h.N.");
	    m_admin = Name.fromString("M.a.n.");
	    m_serial = 0xABCDEF12L;
	    m_refresh = 0xCDEF1234L;
	    m_retry = 0xEF123456L;
	    m_expire = 0x12345678L;
	    m_minimum = 0x3456789AL;
	}

    @Test
    void test_canonical()
	{
	    byte[] exp = new byte[] {
		1, 'm', 1, 'h', 1, 'n', 0, // host
		1, 'm', 1, 'a', 1, 'n', 0, // admin
		(byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0x12,	   // serial
		(byte)0xCD, (byte)0xEF, (byte)0x12, (byte)0x34,	   // refresh
		(byte)0xEF, (byte)0x12, (byte)0x34, (byte)0x56,	   // retry
		(byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,	   // expire
		(byte)0x34, (byte)0x56, (byte)0x78, (byte)0x9A };  // minimum

	    SOARecord ar = new SOARecord(m_an, DClass.IN, m_ttl,
					 m_host, m_admin, m_serial, m_refresh,
					 m_retry, m_expire, m_minimum);
	    DNSOutput o = new DNSOutput();
	    ar.rrToWire(o, null, true);

		assertArrayEquals(exp, o.toByteArray());
	}

    @Test
    void test_case_sensitive()
	{
	    byte[] exp = new byte[] {
		1, 'M', 1, 'h', 1, 'N', 0, // host
		1, 'M', 1, 'a', 1, 'n', 0, // admin
		(byte)0xAB, (byte)0xCD, (byte)0xEF, (byte)0x12,	   // serial
		(byte)0xCD, (byte)0xEF, (byte)0x12, (byte)0x34,	   // refresh
		(byte)0xEF, (byte)0x12, (byte)0x34, (byte)0x56,	   // retry
		(byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,	   // expire
		(byte)0x34, (byte)0x56, (byte)0x78, (byte)0x9A };  // minimum

	    SOARecord ar = new SOARecord(m_an, DClass.IN, m_ttl,
					 m_host, m_admin, m_serial, m_refresh,
					 m_retry, m_expire, m_minimum);
	    DNSOutput o = new DNSOutput();
	    ar.rrToWire(o, null, false);

		assertArrayEquals(exp, o.toByteArray());
	}
    }
}

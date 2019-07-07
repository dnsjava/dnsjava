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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.Iterator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RRsetTest
{
    private RRset m_rs;
    private Name m_name;
	private Name m_name2;
    private long m_ttl;
    private ARecord m_a1;
	private ARecord m_a2;
    private RRSIGRecord m_s1;
	private RRSIGRecord m_s2;

   @BeforeEach
   void setUp() throws TextParseException, UnknownHostException
    {
	m_rs = new RRset();
	m_name = Name.fromString("this.is.a.test.");
	m_name2 = Name.fromString("this.is.another.test.");
	m_ttl = 0xABCDL;
	m_a1 = new ARecord(m_name, DClass.IN, m_ttl,
			   InetAddress.getByName("192.169.232.11"));
	m_a2 = new ARecord(m_name, DClass.IN, m_ttl+1,
			   InetAddress.getByName("192.169.232.12"));

	m_s1 = new RRSIGRecord(m_name, DClass.IN, m_ttl, Type.A, 0xF, 0xABCDEL,
			       new Date(), new Date(), 0xA, m_name,
			       new byte[ 0 ]);
	m_s2 = new RRSIGRecord(m_name, DClass.IN, m_ttl, Type.A, 0xF, 0xABCDEL,
			       new Date(), new Date(), 0xA, m_name2,
			       new byte[ 0 ]);
    }

    @Test
    void test_ctor_0arg()
    {
	assertEquals(0, m_rs.size());
	assertThrows(IllegalStateException.class, () -> m_rs.getDClass());
	assertThrows(IllegalStateException.class, () -> m_rs.getType());
	assertThrows(IllegalStateException.class, () -> m_rs.getTTL());
	assertThrows(IllegalStateException.class, () -> m_rs.getName());
	assertThrows(IllegalStateException.class, () -> m_rs.first());

	assertEquals("{empty}", m_rs.toString());

	Iterator<Record> itr = m_rs.rrs();
	assertNotNull(itr);
	assertFalse(itr.hasNext());

	itr = m_rs.sigs();
	assertNotNull(itr);
	assertFalse(itr.hasNext());
    }

    @Test
    void test_basics() {
	m_rs.addRR(m_a1);

	assertEquals(1, m_rs.size());
	assertEquals(DClass.IN, m_rs.getDClass());
	assertEquals(m_a1, m_rs.first());
	assertEquals(m_name, m_rs.getName());
	assertEquals(m_ttl, m_rs.getTTL());
	assertEquals(Type.A, m_rs.getType());

	// add it again, and make sure nothing changed
	m_rs.addRR(m_a1);

	assertEquals(1, m_rs.size());
	assertEquals(DClass.IN, m_rs.getDClass());
	assertEquals(m_a1, m_rs.first());
	assertEquals(m_name, m_rs.getName());
	assertEquals(m_ttl, m_rs.getTTL());
	assertEquals(Type.A, m_rs.getType());

	m_rs.addRR(m_a2);

	assertEquals(2, m_rs.size());
	assertEquals(DClass.IN, m_rs.getDClass());
	Record r = m_rs.first();
	assertEquals(m_a1, r);
	assertEquals(m_name, m_rs.getName());
	assertEquals(m_ttl, m_rs.getTTL());
	assertEquals(Type.A, m_rs.getType());

	Iterator<Record> itr = m_rs.rrs();
	assertEquals(m_a1, itr.next());
	assertEquals(m_a2, itr.next());

	// make sure that it rotates
	itr = m_rs.rrs();
	assertEquals(m_a2, itr.next());
	assertEquals(m_a1, itr.next());
	itr = m_rs.rrs();
	assertEquals(m_a1, itr.next());
	assertEquals(m_a2, itr.next());

	m_rs.deleteRR(m_a1);
	assertEquals(1, m_rs.size());
	assertEquals(DClass.IN, m_rs.getDClass());
	assertEquals(m_a2, m_rs.first());
	assertEquals(m_name, m_rs.getName());
	assertEquals(m_ttl, m_rs.getTTL());
	assertEquals(Type.A, m_rs.getType());

	// the signature records
	m_rs.addRR(m_s1);
	assertEquals(1, m_rs.size());
	itr = m_rs.sigs();
	assertEquals(m_s1, itr.next());
	assertFalse(itr.hasNext());

	m_rs.addRR(m_s1);
	itr = m_rs.sigs();
	assertEquals(m_s1, itr.next());
	assertFalse(itr.hasNext());

	m_rs.addRR(m_s2);
	itr = m_rs.sigs();
	assertEquals(m_s1, itr.next());
	assertEquals(m_s2, itr.next());
	assertFalse(itr.hasNext());

	m_rs.deleteRR(m_s1);
	itr = m_rs.sigs();
	assertEquals(m_s2, itr.next());
	assertFalse(itr.hasNext());

	
	// clear it all
	m_rs.clear();
	assertEquals(0, m_rs.size());
	assertFalse(m_rs.rrs().hasNext());
	assertFalse(m_rs.sigs().hasNext());

    }

    @Test
    void test_ctor_1arg()
    {
	m_rs.addRR(m_a1);
	m_rs.addRR(m_a2);
	m_rs.addRR(m_s1);
	m_rs.addRR(m_s2);

	RRset rs2 = new RRset( m_rs );

	assertEquals(2, rs2.size());
	assertEquals(m_a1, rs2.first());
	Iterator<Record> itr = rs2.rrs();
	assertEquals(m_a1, itr.next());
	assertEquals(m_a2, itr.next());
	assertFalse(itr.hasNext());
	
	itr = rs2.sigs();
	assertTrue(itr.hasNext());
	assertEquals(m_s1, itr.next());
	assertTrue(itr.hasNext());
	assertEquals(m_s2, itr.next());
	assertFalse(itr.hasNext());
    }

    @Test
    void test_toString()
    {
	m_rs.addRR(m_a1);
	m_rs.addRR(m_a2);
	m_rs.addRR(m_s1);
	m_rs.addRR(m_s2);

	String out = m_rs.toString();
	
	assertTrue(out.contains(m_name.toString()));
	assertTrue(out.contains(" IN A "));
	assertTrue(out.contains("[192.169.232.11]"));
	assertTrue(out.contains("[192.169.232.12]"));
    }

    @Test
    void test_addRR_invalidType() throws TextParseException
    {
	m_rs.addRR(m_a1);
	
	CNAMERecord c = new CNAMERecord(m_name, DClass.IN, m_ttl, Name.fromString("an.alias."));
	
	assertThrows(IllegalArgumentException.class, () -> m_rs.addRR(c));
    }

    @Test
    void test_addRR_invalidName() throws UnknownHostException
    {
	m_rs.addRR(m_a1);
	
	m_a2 = new ARecord(m_name2, DClass.IN, m_ttl,
			   InetAddress.getByName("192.169.232.11"));
	
	assertThrows(IllegalArgumentException.class, () -> m_rs.addRR(m_a2));
    }

    @Test
    void test_addRR_invalidDClass() throws UnknownHostException
    {
	m_rs.addRR(m_a1);
	
	m_a2 = new ARecord(m_name, DClass.CHAOS, m_ttl,
			   InetAddress.getByName("192.169.232.11"));
	
	assertThrows(IllegalArgumentException.class, () -> m_rs.addRR(m_a2));
    }

    @Test
    void test_TTLcalculation()
    {
	m_rs.addRR(m_a2);
	assertEquals(m_a2.getTTL(), m_rs.getTTL());
	m_rs.addRR(m_a1);
	assertEquals(m_a1.getTTL(), m_rs.getTTL());

	Iterator<Record> itr = m_rs.rrs();
	while( itr.hasNext() ){
	    Record r = (Record)itr.next();
	    assertEquals( m_a1.getTTL(), r.getTTL());
	}
    }

    @Test
    void test_Record_placement()
    {
	m_rs.addRR(m_a1);
	m_rs.addRR(m_s1);
	m_rs.addRR(m_a2);

	Iterator<Record> itr = m_rs.rrs();
	assertTrue(itr.hasNext());
	assertEquals(m_a1, itr.next());
	assertTrue(itr.hasNext());
	assertEquals(m_a2, itr.next());
	assertFalse(itr.hasNext());

	itr = m_rs.sigs();
	assertTrue(itr.hasNext());
	assertEquals(m_s1, itr.next());
	assertFalse(itr.hasNext());
    }

    @Test
    void test_noncycling_iterator()
    {
	m_rs.addRR(m_a1);
	m_rs.addRR(m_a2);

	Iterator<Record> itr = m_rs.rrs(false);
	assertTrue(itr.hasNext());
	assertEquals(m_a1, itr.next());
	assertTrue(itr.hasNext());
	assertEquals(m_a2, itr.next());

	itr = m_rs.rrs(false);
	assertTrue(itr.hasNext());
	assertEquals(m_a1, itr.next());
	assertTrue(itr.hasNext());
	assertEquals(m_a2, itr.next());
    }
}

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

// Mnemonic has package-level access.

import junit.framework.TestCase;

public class MnemonicTest extends TestCase
{
    private Mnemonic m_mn;

    public MnemonicTest( String name )
    {
	super( name );
    }
    
    public void setUp()
    {
	m_mn = new Mnemonic(MnemonicTest.class.getName() + " UPPER", Mnemonic.CASE_UPPER);
    }

    public void test_toInteger()
    {
	Integer i = Mnemonic.toInteger(64);
	assertEquals( new Integer(64), i );
	Integer i2 = Mnemonic.toInteger(64);
	assertEquals( i, i2 );
	assertNotSame( i, i2 );

	i = Mnemonic.toInteger(-1);
	assertEquals( new Integer(-1), i );
	i2 = Mnemonic.toInteger(-1);
	assertEquals( i, i2 );
	assertNotSame( i, i2 );

	i = Mnemonic.toInteger(0);
	assertEquals( new Integer(0), i );
	i2 = Mnemonic.toInteger(0);
	assertEquals( i, i2 );
	assertSame( i, i2 );

	i = Mnemonic.toInteger(63);
	assertEquals( new Integer(63), i );
	i2 = Mnemonic.toInteger(63);
	assertEquals( i, i2 );
	assertSame( i, i2 );
    }

    public void test_no_maximum()
    {
	try {m_mn.check(-1); fail( "IllegalArgumentException not thrown" );} catch( IllegalArgumentException e ){}
	try {m_mn.check(0);} catch( IllegalArgumentException e ){fail(e.getMessage());}
	try {m_mn.check(Integer.MAX_VALUE);} catch( IllegalArgumentException e ){fail(e.getMessage());}

	m_mn.setNumericAllowed(true);

	int val = m_mn.getValue("-2");
	assertEquals( -1, val );
	
	val = m_mn.getValue("0");
	assertEquals( 0, val );
       
	val = m_mn.getValue("" + Integer.MAX_VALUE);
	assertEquals( Integer.MAX_VALUE, val );
    }

    public void test_setMaximum()
    {
	m_mn.setMaximum(15);
	try {m_mn.check(-1); fail("IllegalArgumentException not thrown");} catch( IllegalArgumentException e ){}
	try {m_mn.check(0);} catch( IllegalArgumentException e ){fail( e.getMessage() );}
	try {m_mn.check(15);} catch( IllegalArgumentException e ){fail( e.getMessage() );}
	try {m_mn.check(16); fail("IllegalArgumentException not thrown");} catch( IllegalArgumentException e ){}

	// need numericok to exercise the usage of max in parseNumeric
	m_mn.setNumericAllowed(true);
	
	int val = m_mn.getValue("-2");
	assertEquals( -1, val );
	
	val = m_mn.getValue( "0" );
	assertEquals( 0, val );

	val = m_mn.getValue( "15" );
	assertEquals( 15, val );

	val = m_mn.getValue( "16" );
	assertEquals( -1, val );
    }

    public void test_setPrefix()
    {
	final String prefix = "A mixed CASE Prefix".toUpperCase();
	m_mn.setPrefix(prefix);

	String out = m_mn.getText(10);
	assertEquals( prefix + "10", out );

	int i = m_mn.getValue( out );
	assertEquals( 10, i );
    }

    public void test_basic_operation()
    {
	// setUp creates Mnemonic with CASE_UPPER
	m_mn.add( 10, "Ten" );
	m_mn.add( 20, "Twenty" );
	m_mn.addAlias( 20, "Veinte" );
	m_mn.add( 30, "Thirty" );

	String text = m_mn.getText(10);
	assertEquals( "TEN", text );
	
	text = m_mn.getText(20);
	assertEquals( "TWENTY", text );
	
	text = m_mn.getText(30);
	assertEquals( "THIRTY", text );

	text = m_mn.getText(40);
	assertEquals( "40", text );

	int value = m_mn.getValue("tEn");
	assertEquals(10, value);

	value = m_mn.getValue("twenty");
	assertEquals(20, value);

	value = m_mn.getValue("VeiNTe");
	assertEquals(20, value);

	value = m_mn.getValue("THIRTY");
	assertEquals(30, value);
    }

    public void test_basic_operation_lower()
    {
	m_mn = new Mnemonic(MnemonicTest.class.getName() + " LOWER", Mnemonic.CASE_LOWER);
	m_mn.add( 10, "Ten" );
	m_mn.add( 20, "Twenty" );
	m_mn.addAlias( 20, "Veinte" );
	m_mn.add( 30, "Thirty" );

	String text = m_mn.getText(10);
	assertEquals( "ten", text );
	
	text = m_mn.getText(20);
	assertEquals( "twenty", text );
	
	text = m_mn.getText(30);
	assertEquals( "thirty", text );

	text = m_mn.getText(40);
	assertEquals( "40", text );

	int value = m_mn.getValue("tEn");
	assertEquals(10, value);

	value = m_mn.getValue("twenty");
	assertEquals(20, value);

	value = m_mn.getValue("VeiNTe");
	assertEquals(20, value);

	value = m_mn.getValue("THIRTY");
	assertEquals(30, value);
    }

    public void test_basic_operation_sensitive()
    {
	m_mn = new Mnemonic(MnemonicTest.class.getName() + " SENSITIVE", Mnemonic.CASE_SENSITIVE);
	m_mn.add( 10, "Ten" );
	m_mn.add( 20, "Twenty" );
	m_mn.addAlias( 20, "Veinte" );
	m_mn.add( 30, "Thirty" );

	String text = m_mn.getText(10);
	assertEquals( "Ten", text );
	
	text = m_mn.getText(20);
	assertEquals( "Twenty", text );
	
	text = m_mn.getText(30);
	assertEquals( "Thirty", text );

	text = m_mn.getText(40);
	assertEquals( "40", text );

	int value = m_mn.getValue("Ten");
	assertEquals(10, value);

	value = m_mn.getValue("twenty");
	assertEquals(-1, value);

	value = m_mn.getValue("Twenty");
	assertEquals(20, value);

	value = m_mn.getValue("VEINTE");
	assertEquals(-1, value);

	value = m_mn.getValue("Veinte");
	assertEquals(20, value);

	value = m_mn.getValue("Thirty");
	assertEquals(30, value);
    }

    public void test_invalid_numeric()
    {
	m_mn.setNumericAllowed(true);
	int value = m_mn.getValue("Not-A-Number");
	assertEquals(-1, value);
    }

    public void test_addAll()
    {
	m_mn.add( 10, "Ten" );
	m_mn.add( 20, "Twenty" );

	Mnemonic mn2 = new Mnemonic("second test Mnemonic", Mnemonic.CASE_UPPER);
	mn2.add( 20, "Twenty" );
	mn2.addAlias( 20, "Veinte" );
	mn2.add( 30, "Thirty" );

	m_mn.addAll( mn2 );

	String text = m_mn.getText(10);
	assertEquals( "TEN", text );
	
	text = m_mn.getText(20);
	assertEquals( "TWENTY", text );
	
	text = m_mn.getText(30);
	assertEquals( "THIRTY", text );

	text = m_mn.getText(40);
	assertEquals( "40", text );

	int value = m_mn.getValue("tEn");
	assertEquals(10, value);

	value = m_mn.getValue("twenty");
	assertEquals(20, value);

	value = m_mn.getValue("VeiNTe");
	assertEquals(20, value);

	value = m_mn.getValue("THIRTY");
	assertEquals(30, value);
    }
}

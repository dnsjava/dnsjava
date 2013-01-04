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

import junit.framework.TestCase;

public class OptionsTest extends TestCase
{
    public void setUp()
    {
	// reset the options table before each test
	Options.clear();
    }

    public void test_set_1arg()
    {
	Options.set("Option1");
	assertEquals("true", Options.value("option1"));

	Options.set("OPTION2");
	assertEquals("true", Options.value("option1"));
	assertEquals("true", Options.value("OpTIOn2"));

	Options.set("option2");
	assertEquals("true", Options.value("option2"));
    }

    public void test_set_2arg()
    {
	Options.set("OPTION1", "Value1");
	assertEquals("value1", Options.value("Option1"));

	Options.set("option2", "value2");
	assertEquals("value1", Options.value("Option1"));
	assertEquals("value2", Options.value("OPTION2"));

	Options.set("OPTION2", "value2b");
	assertEquals("value1", Options.value("Option1"));
	assertEquals("value2b", Options.value("option2"));
    }

    public void test_check()
    {
	assertFalse(Options.check("No Options yet"));

	Options.set("First Option");
	assertFalse(Options.check("Not a valid option name"));
	assertTrue(Options.check("First Option"));
	assertTrue(Options.check("FIRST option"));
    }

    public void test_unset()
    {
	// unset something non-existant
	Options.unset("Not an option Name");

	Options.set("Temporary Option");
	assertTrue(Options.check("Temporary Option"));
	Options.unset("Temporary Option");
	assertFalse(Options.check("Temporary Option"));
	
	Options.set("Temporary Option");
	assertTrue(Options.check("Temporary Option"));
	Options.unset("temporary option");
	assertFalse(Options.check("Temporary Option"));

	// unset something now that the table is non-null
	Options.unset("Still Not an Option Name");
    }

    public void test_value()
    {
	assertNull(Options.value("Table is Null"));

	Options.set("Testing Option");
	assertNull(Options.value("Not an Option Name"));

	assertEquals("true", Options.value("Testing OPTION"));
    }

    public void test_intValue()
    {
	assertEquals(-1, Options.intValue("Table is Null"));

	Options.set("A Boolean Option");
	Options.set("An Int Option", "13");
	Options.set("Not An Int Option", "NotAnInt");
	Options.set("A Negative Int Value", "-1000");

	assertEquals(-1, Options.intValue("A Boolean Option"));
	assertEquals(-1, Options.intValue("Not an Option NAME"));
	assertEquals(13, Options.intValue("an int option"));
	assertEquals(-1, Options.intValue("NOT an INT option"));
	assertEquals(-1, Options.intValue("A negative int Value"));
    }

    public void test_systemProperty()
    {
	System.setProperty("dnsjava.options", "booleanOption,valuedOption1=10,valuedOption2=NotAnInteger");
	
	Options.refresh();

	assertTrue(Options.check("booleanOPTION"));
	assertTrue(Options.check("booleanOption"));
	assertTrue(Options.check("valuedOption1"));
	assertTrue(Options.check("ValuedOption2"));

	assertEquals("true", Options.value("booleanOption"));
	assertEquals(-1, Options.intValue("BOOLEANOPTION"));
	assertEquals("10", Options.value("valuedOption1"));
	assertEquals(10, Options.intValue("valuedOption1"));
	assertEquals("notaninteger", Options.value("VALUEDOPTION2"));
	assertEquals(-1, Options.intValue("valuedOption2"));
    }
}

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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenizerTest
{
    private Tokenizer m_t;

   @BeforeEach
   void setUp()
    {
	m_t = null;
    }

    @Test
    void test_get() throws IOException
    {
	m_t = new Tokenizer(new BufferedInputStream(new ByteArrayInputStream("AnIdentifier \"a quoted \\\" string\"\r\n; this is \"my\"\t(comment)\nanotherIdentifier (\ramultilineIdentifier\n)".getBytes())));

	Tokenizer.Token tt = m_t.get(true, true);
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertTrue(tt.isString());
	assertFalse(tt.isEOL());
	assertEquals("AnIdentifier", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.WHITESPACE, tt.type);
	assertFalse(tt.isString());
	assertFalse(tt.isEOL());
	assertNull(tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.QUOTED_STRING, tt.type);
	assertTrue(tt.isString());
	assertFalse(tt.isEOL());
	assertEquals("a quoted \\\" string", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOL, tt.type);
	assertFalse(tt.isString());
	assertTrue(tt.isEOL());
	assertNull(tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.COMMENT, tt.type);
	assertFalse(tt.isString());
	assertFalse(tt.isEOL());
	assertEquals(" this is \"my\"\t(comment)", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOL, tt.type);
	assertFalse(tt.isString());
	assertTrue(tt.isEOL());
	assertNull(tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertTrue(tt.isString());
	assertFalse(tt.isEOL());
	assertEquals("anotherIdentifier", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.WHITESPACE, tt.type);
	
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertTrue(tt.isString());
	assertFalse(tt.isEOL());
	assertEquals("amultilineIdentifier", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.WHITESPACE, tt.type);
	
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOF, tt.type);
	assertFalse(tt.isString());
	assertTrue(tt.isEOL());
	assertNull(tt.value);

	// should be able to do this repeatedly
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOF, tt.type);
	assertFalse(tt.isString());
	assertTrue(tt.isEOL());
	assertNull(tt.value);

	m_t = new Tokenizer("onlyOneIdentifier");
	tt = m_t.get();
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertEquals("onlyOneIdentifier", tt.value);

	m_t = new Tokenizer("identifier ;");
	tt = m_t.get();
	assertEquals("identifier", tt.value);
	tt = m_t.get();
	assertEquals(Tokenizer.EOF, tt.type);


	// some ungets
	m_t = new Tokenizer("identifier \nidentifier2; junk comment");
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertEquals("identifier", tt.value);

	m_t.unget();

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertEquals("identifier", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.WHITESPACE, tt.type);
	
	m_t.unget();
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.WHITESPACE, tt.type);
	
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOL, tt.type);
	
	m_t.unget();
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOL, tt.type);
	
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertEquals("identifier2", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.COMMENT, tt.type);
	assertEquals(" junk comment", tt.value);

	m_t.unget();
	tt = m_t.get(true, true);
	assertEquals(Tokenizer.COMMENT, tt.type);
	assertEquals(" junk comment", tt.value);

	tt = m_t.get(true, true);
	assertEquals(Tokenizer.EOF, tt.type);
	
	m_t = new Tokenizer("identifier ( junk ; comment\n )");
	tt = m_t.get();
	assertEquals(Tokenizer.IDENTIFIER, tt.type);
	assertEquals(Tokenizer.IDENTIFIER, m_t.get().type);
	assertEquals(Tokenizer.EOF, m_t.get().type);
    }

    @Test
    void test_get_invalid() throws IOException
    {
	m_t = new Tokenizer("(this ;");
	m_t.get();
	assertThrows(TextParseException.class, () -> m_t.get());

	m_t = new Tokenizer("\"bad");
	assertThrows(TextParseException.class, () -> m_t.get());
	
	m_t = new Tokenizer(")");
	assertThrows(TextParseException.class, () -> m_t.get());
	
	m_t = new Tokenizer("\\");
	assertThrows(TextParseException.class, () -> m_t.get());

	m_t = new Tokenizer("\"\n");
	assertThrows(TextParseException.class, () -> m_t.get());
    }

    @Test
    void test_File_input() throws IOException
    {
	File tmp = File.createTempFile("dnsjava", "tmp");
	try {
	    FileWriter fw = new FileWriter(tmp);
	    fw.write("file\ninput; test");
	    fw.close();

	    m_t = new Tokenizer(tmp);

	    Tokenizer.Token tt = m_t.get();
	    assertEquals(Tokenizer.IDENTIFIER, tt.type);
	    assertEquals("file", tt.value);

	    tt = m_t.get();
	    assertEquals(Tokenizer.EOL, tt.type);

	    tt = m_t.get();
	    assertEquals(Tokenizer.IDENTIFIER, tt.type);
	    assertEquals("input", tt.value);

	    tt = m_t.get(false, true);
	    assertEquals(Tokenizer.COMMENT, tt.type);
	    assertEquals(" test", tt.value);

	    m_t.close();
	}
	finally {
	    tmp.delete();
	}
    }

    @Test
    void test_unwanted_comment() throws IOException
    {
	m_t = new Tokenizer("; this whole thing is a comment\n");
	Tokenizer.Token tt = m_t.get();

	assertEquals(Tokenizer.EOL, tt.type);
    }

    @Test
    void test_unwanted_ungotten_whitespace() throws IOException
    {
	m_t = new Tokenizer(" ");
	Tokenizer.Token tt = m_t.get(true, true);
	m_t.unget();
	tt = m_t.get();
	assertEquals(Tokenizer.EOF, tt.type);
    }

    @Test
    void test_unwanted_ungotten_comment() throws IOException
    {
	m_t = new Tokenizer("; this whole thing is a comment");
	Tokenizer.Token tt = m_t.get(true, true);
	m_t.unget();
	tt = m_t.get();
	assertEquals(Tokenizer.EOF, tt.type);
    }

    @Test
    void test_empty_string() throws IOException
    {
	m_t = new Tokenizer("");
	Tokenizer.Token tt = m_t.get();
	assertEquals(Tokenizer.EOF, tt.type);

	m_t = new Tokenizer(" ");
	tt = m_t.get();
	assertEquals(Tokenizer.EOF, tt.type);
    }

    @Test
    void test_multiple_ungets() throws IOException
    {
	m_t = new Tokenizer("a simple one");
	Tokenizer.Token tt = m_t.get();

	m_t.unget();
	assertThrows(IllegalStateException.class, () -> m_t.unget());
    }

    @Test
    void test_getString() throws IOException
    {
	m_t = new Tokenizer("just_an_identifier");
	    final String[] out = {m_t.getString()};
	assertEquals("just_an_identifier", out[0]);

	m_t = new Tokenizer("\"just a string\"");
	out[0] = m_t.getString();
	assertEquals("just a string", out[0]);

	m_t = new Tokenizer("; just a comment");
	assertThrows(TextParseException.class, () -> out[0] = m_t.getString());
    }

    @Test
    void test_getIdentifier() throws IOException
    {
	m_t = new Tokenizer("just_an_identifier");
	String out = m_t.getIdentifier();
	assertEquals("just_an_identifier", out);

	m_t = new Tokenizer("\"just a string\"");
	assertThrows(TextParseException.class, () -> m_t.getIdentifier());
    }

    @Test
    void test_getLong() throws IOException
    {
	m_t = new Tokenizer((Integer.MAX_VALUE+1L) + "");
	long out = m_t.getLong();
	assertEquals((Integer.MAX_VALUE+1L), out);

	m_t = new Tokenizer("-10");
	assertThrows(TextParseException.class, () -> m_t.getLong());

	m_t = new Tokenizer("19_identifier");
	assertThrows(TextParseException.class, () -> m_t.getLong());
    }

    @Test
    void test_getUInt32() throws IOException
    {
	m_t = new Tokenizer(0xABCDEF12L + "");
	long out = m_t.getUInt32();
	assertEquals(0xABCDEF12L, out);

	m_t = new Tokenizer(0x100000000L + "");
	assertThrows(TextParseException.class, () -> m_t.getUInt32());

	m_t = new Tokenizer("-12345");
	assertThrows(TextParseException.class, () -> m_t.getUInt32());
    }

    @Test
    void test_getUInt16() throws IOException
    {
	m_t = new Tokenizer(0xABCDL + "");
	int out = m_t.getUInt16();
	assertEquals(0xABCDL, out);

	m_t = new Tokenizer(0x10000 + "");
	assertThrows(TextParseException.class, () -> m_t.getUInt16());

	m_t = new Tokenizer("-125");
	assertThrows(TextParseException.class, () -> m_t.getUInt16());
    }

    @Test
    void test_getUInt8() throws IOException
    {
	m_t = new Tokenizer(0xCDL + "");
	int out = m_t.getUInt8();
	assertEquals(0xCDL, out);

	m_t = new Tokenizer(0x100 + "");
	assertThrows(TextParseException.class, () -> m_t.getUInt8());

	m_t = new Tokenizer("-12");
	assertThrows(TextParseException.class, () -> m_t.getUInt8());
    }

    @Test
    void test_getTTL() throws IOException
    {
	m_t = new Tokenizer("59S");
	assertEquals(59, m_t.getTTL());

	m_t = new Tokenizer(TTL.MAX_VALUE + "");
	assertEquals(TTL.MAX_VALUE, m_t.getTTL());

	m_t = new Tokenizer((TTL.MAX_VALUE+1L) + "");
	assertEquals(TTL.MAX_VALUE, m_t.getTTL());

	m_t = new Tokenizer("Junk");
	assertThrows(TextParseException.class, () -> m_t.getTTL());
    }

    @Test
    void test_getTTLLike() throws IOException
    {
	m_t = new Tokenizer("59S");
	assertEquals(59, m_t.getTTLLike());

	m_t = new Tokenizer(TTL.MAX_VALUE + "");
	assertEquals(TTL.MAX_VALUE, m_t.getTTLLike());

	m_t = new Tokenizer((TTL.MAX_VALUE+1L) + "");
	assertEquals(TTL.MAX_VALUE+1L, m_t.getTTLLike());

	m_t = new Tokenizer("Junk");
	assertThrows(TextParseException.class, () -> m_t.getTTLLike());
    }

    @Test
    void test_getName() throws IOException {
	Name root = Name.fromString(".");
	m_t = new Tokenizer("junk");
	Name exp = Name.fromString("junk.");
	Name out = m_t.getName(root);
	assertEquals(exp, out);

	Name rel = Name.fromString("you.dig");
	m_t = new Tokenizer("junk");
	assertThrows(RelativeNameException.class, () -> m_t.getName(rel));

	m_t = new Tokenizer("");
	assertThrows(TextParseException.class, () -> m_t.getName(root));
    }

    @Test
    void test_getEOL() throws IOException
    {
	m_t = new Tokenizer("id");
	m_t.getIdentifier();
	try {
	    m_t.getEOL();
	}
	catch( TextParseException e ){
	    fail(e.getMessage());
	}

	m_t = new Tokenizer("\n");
	try {
	    m_t.getEOL();
	    m_t.getEOL();
	}
	catch( TextParseException e ){
	    fail(e.getMessage());
	}

	m_t = new Tokenizer("id");
	assertThrows(TextParseException.class, () -> m_t.getEOL());
    }

    @Test
    void test_getBase64() throws IOException
    {
	byte[] exp = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	// basic
	m_t = new Tokenizer("AQIDBAUGBwgJ");
	byte[] out = m_t.getBase64();
	assertArrayEquals(exp, out);

	// with some whitespace
	m_t = new Tokenizer("AQIDB AUGB   wgJ");
	out = m_t.getBase64();
	assertArrayEquals(exp, out);

	// two base64s separated by newline
	m_t = new Tokenizer("AQIDBAUGBwgJ\nAB23DK");
	out = m_t.getBase64();
	assertArrayEquals(exp, out);

	// no remaining strings
	m_t = new Tokenizer("\n");
	assertNull( m_t.getBase64() );

	m_t = new Tokenizer("\n");
	assertThrows(TextParseException.class, () -> m_t.getBase64(true));

	// invalid encoding
	m_t = new Tokenizer("not_base64");
	assertThrows(TextParseException.class, () -> m_t.getBase64(false));

	m_t = new Tokenizer("not_base64");
	assertThrows(TextParseException.class, () -> m_t.getBase64(true));
    }

    @Test
    void test_getHex() throws IOException
    {
	byte[] exp = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	// basic
	m_t = new Tokenizer("0102030405060708090A0B0C0D0E0F");
	byte[] out = m_t.getHex();
	assertArrayEquals(exp, out);

	// with some whitespace
	m_t = new Tokenizer("0102030 405 060708090A0B0C      0D0E0F");
	out = m_t.getHex();
	assertArrayEquals(exp, out);

	// two hexs separated by newline
	m_t = new Tokenizer("0102030405060708090A0B0C0D0E0F\n01AB3FE");
	out = m_t.getHex();
	assertArrayEquals(exp, out);

	// no remaining strings
	m_t = new Tokenizer("\n");
	assertNull( m_t.getHex() );

	m_t = new Tokenizer("\n");
	assertThrows(TextParseException.class, () -> m_t.getHex(true));

	// invalid encoding
	m_t = new Tokenizer("not_hex");
	assertThrows(TextParseException.class, () -> m_t.getHex(false));

	m_t = new Tokenizer("not_hex");
	assertThrows(TextParseException.class, () -> m_t.getHex(true));
    }
}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Text - stores text strings
 *
 * @author Brian Wellington
 */

public class TXTRecord extends Record {

private static TXTRecord member = new TXTRecord();

private List strings;

private
TXTRecord() {}

private
TXTRecord(Name name, int dclass, int ttl) {
	super(name, Type.TXT, dclass, ttl);
}

static TXTRecord
getMember() {
	return member;
}

/**
 * Creates a TXT Record from the given data
 * @param strings The text strings
 * @throws IllegalArgumentException One of the strings has invalid escapes
 */
public
TXTRecord(Name name, int dclass, int ttl, List strings) {
	this(name, dclass, ttl);
	if (strings == null)
		throw new IllegalArgumentException
				("TXTRecord: strings must not be null");
	this.strings = new ArrayList();
	Iterator it = strings.iterator();
	try {
		while (it.hasNext()) {
			String s = (String) it.next();
			this.strings.add(byteArrayFromString(s));
		}
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException(e.getMessage());
	}
}

/**
 * Creates a TXT Record from the given data
 * @param strings One text string
 * @throws IllegalArgumentException The string has invalid escapes
 */
public
TXTRecord(Name name, int dclass, int ttl, String string) {
	this(name, dclass, ttl, Collections.nCopies(1, string));
}

Record
rrFromWire(Name name, int type, int dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	TXTRecord rec = new TXTRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	int count = 0;
	rec.strings = new ArrayList();
	while (count < length) {
		byte [] b = in.readStringIntoArray();
		count += (b.length + 1);
		rec.strings.add(b);
	}
	return rec;
}

Record
rdataFromString(Name name, int dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	TXTRecord rec = new TXTRecord(name, dclass, ttl);
	rec.strings = new ArrayList();
	while (true) {
		Tokenizer.Token t = st.get();
		if (!t.isString())
			break;
		try {
			rec.strings.add(byteArrayFromString(t.value));
		}
		catch (TextParseException e) { 
			throw st.exception(e.getMessage());
		}

	}
	st.unget();
	return rec;
}

/** converts to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (strings != null) {
		Iterator it = strings.iterator();
		while (it.hasNext()) {
			byte [] array = (byte []) it.next();
			sb.append(byteArrayToString(array, true));
			if (it.hasNext())
				sb.append(" ");
		}
	}
	return sb.toString();
}

/** Returns the text strings */
public List
getStrings() {
	return strings;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (strings == null)
		return;

	Iterator it = strings.iterator();
	while (it.hasNext()) {
		byte [] b = (byte []) it.next();
		out.writeArray(b, true);
	}
}

}

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
TXTRecord(Name name, short dclass, int ttl) {
	super(name, Type.TXT, dclass, ttl);
}

static TXTRecord
getMember() {
	return member;
}

/**
 * Creates a TXT Record from the given data
 * @param strings The text strings
 */
public
TXTRecord(Name name, short dclass, int ttl, List strings) {
	this(name, dclass, ttl);
	if (strings == null)
		throw new IllegalArgumentException
				("TXTRecord: strings must not be null");
	this.strings = new ArrayList();
	Iterator it = strings.iterator();
	while (it.hasNext())
		this.strings.add(byteArrayFromString((String)it.next()));
}

/**
 * Creates a TXT Record from the given data
 * @param strings One text string
 */
public
TXTRecord(Name name, short dclass, int ttl, String string) {
	this(name, dclass, ttl);
	this.strings = new ArrayList();
	this.strings.add(byteArrayFromString(string));
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
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
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	TXTRecord rec = new TXTRecord(name, dclass, ttl);
	rec.strings = new ArrayList();
	while (st.hasMoreTokens())
		rec.strings.add(byteArrayFromString(nextString(st)));
	return rec;
}

/** converts to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (strings != null) {
		Iterator it = strings.iterator();
		while (it.hasNext()) {
			String s = byteArrayToString((byte []) it.next());
			sb.append("\"");
			sb.append(s);
			sb.append("\"");
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

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
TXTRecord(Name _name, short _dclass, int _ttl, List _strings)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = _strings;
}

/**
 * Creates a TXT Record from the given data
 * @param strings One text string
 */
public
TXTRecord(Name _name, short _dclass, int _ttl, String _string)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = new ArrayList();
	strings.add(_string);
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
                int len = in.readByte();
                byte [] b = new byte[len];
                in.read(b);
                count += (len + 1);
                rec.strings.add(new String(b));
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
		rec.strings.add(st.nextToken());
	return rec;
}

/** converts to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (strings != null) {
		Iterator it = strings.iterator();
		while (it.hasNext()) {
			String s = (String) it.next();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (strings == null)
		return;

	Iterator it = strings.iterator();
	while (it.hasNext()) {
		String s = (String) it.next();
		out.writeString(s);
	}
}

}

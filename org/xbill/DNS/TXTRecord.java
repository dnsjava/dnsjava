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

private List strings;

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

TXTRecord(Name _name, short _dclass, int _ttl, int length,
	  DataByteInputStream in)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	if (in == null)
		return;
	int count = 0;
	strings = new ArrayList();
        while (count < length) {
                int len = in.readByte();
                byte [] b = new byte[len];
                in.read(b);
                count += (len + 1);
                strings.add(new String(b));
        }
}

TXTRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = new ArrayList();
	while (st.hasMoreTokens())
		strings.add(st.nextToken());
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
			if (it.hasNext())
				sb.append("\" ");
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

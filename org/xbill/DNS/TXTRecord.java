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

private Vector strings;

/**
 * Creates a TXT Record from the given data
 * @param strings The text strings
 */
public
TXTRecord(Name _name, short _dclass, int _ttl, Vector _strings)
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
	strings = new Vector();
	strings.addElement(_string);
}

TXTRecord(Name _name, short _dclass, int _ttl, int length,
	  DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	if (in == null)
		return;
	int count = 0;
	strings = new Vector();
        while (count < length) {
                int len = in.readByte();
                byte [] b = new byte[len];
                in.read(b);
                count += (len + 1);
                strings.addElement(new String(b));
        }
}

TXTRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = new Vector();
	while (st.hasMoreTokens())
		strings.addElement(st.nextToken());
}

/** converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
	if (strings != null) {
		Enumeration e = strings.elements();
		while (e.hasMoreElements()) {
			String s = (String) e.nextElement();
			sb.append("\"");
			sb.append(s);
			sb.append("\" ");
		}
	}
	return sb.toString();
}

/** Returns the text strings */
public Vector
getStrings() {
	return strings;
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (strings == null)
		return;

	Enumeration e = strings.elements();
	while (e.hasMoreElements()) {
		String s = (String) e.nextElement();
		out.writeString(s);
	}
}

}

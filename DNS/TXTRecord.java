// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class TXTRecord extends Record {

Vector strings;

public
TXTRecord(Name _name, short _dclass, int _ttl, Vector _strings)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = _strings;
}

public
TXTRecord(Name _name, short _dclass, int _ttl, String _string)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = new Vector();
	strings.addElement(_string);
}

public
TXTRecord(Name _name, short _dclass, int _ttl,
	     int length, CountedDataInputStream in, Compression c)
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

public
TXTRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.TXT, _dclass, _ttl);
	strings = new Vector();
	while (st.hasMoreTokens())
		strings.addElement(st.nextToken());
}

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

public Vector
getStrings() {
	return strings;
}

void
rrToWire(DataByteOutputStream dbs, Compression c) throws IOException {
	if (strings == null)
		return;

	Enumeration e = strings.elements();
	while (e.hasMoreElements()) {
		String s = (String) e.nextElement();
		dbs.writeString(s);
	}
}

}

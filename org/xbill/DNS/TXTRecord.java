// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsTXTRecord extends dnsRecord {

Vector strings;

public
dnsTXTRecord(dnsName _name, short _type, short _dclass, int _ttl,
	     Vector _strings) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	strings = _strings;
}

public
dnsTXTRecord(dnsName _name, short _type, short _dclass, int _ttl,
	     String _string) throws IOException
{
	super(_name, _type, _dclass, _ttl);
	strings = new Vector();
	strings.addElement(_string);
}

public
dnsTXTRecord(dnsName _name, short _type, short _dclass, int _ttl,
	     int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, _type, _dclass, _ttl);
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
dnsTXTRecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st)
throws IOException
{
	super(_name, dns.TXT, _dclass, _ttl);
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

byte []
rrToWire() throws IOException {
	if (strings == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	Enumeration e = strings.elements();
	while (e.hasMoreElements()) {
		String s = (String) e.nextElement();
		ds.writeByte(s.getBytes().length);
		ds.write(s.getBytes());
	}
	return bs.toByteArray();
}

}

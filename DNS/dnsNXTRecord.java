// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsNXTRecord extends dnsRecord {

dnsName next;
BitSet bitmap;

public
dnsNXTRecord(dnsName _name, short _dclass, int _ttl, dnsName _next,
	     BitSet _bitmap)
{
	super(_name, dns.NXT, _dclass, _ttl);
	next = _next;
	bitmap = _bitmap;
}

public
dnsNXTRecord(dnsName _name, short _dclass, int _ttl,
	     int length, CountedDataInputStream in, dnsCompression c)
throws IOException
{
	super(_name, dns.NXT, _dclass, _ttl);
	if (in == null)
		return;
	int start = in.getPos();
	next = new dnsName(in, c);
	bitmap = new BitSet();
	int bitmapLength = length - (in.getPos() - start);
	for (int i = 0; i < bitmapLength; i++) {
		int t = in.readUnsignedByte();
		for (int j = 0; j < 8; j++)
			if ((t & (1 << (7 - j))) != 0)
				bitmap.set(i * 8 + j);
	}
}

public
dnsNXTRecord(dnsName _name, short _dclass, int _ttl, StringTokenizer st)
throws IOException
{
	super(_name, dns.NXT, _dclass, _ttl);
	Vector types = new Vector();
	next = new dnsName(st.nextToken());
	bitmap = new BitSet();
	while (st.hasMoreTokens()) {
		short t = dns.typeValue(st.nextToken());
		if (t > 0)
			bitmap.set(t);
	}
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	if (next != null) {
		sb.append(next);
		for (int i = 0; i < bitmap.size(); i++)
			if (bitmap.get(i)) {
				sb.append(" ");
				sb.append(dns.typeString(i));
			}
	}
	return sb.toString();
}

public dnsName
getNext() {
	return next;
}

public BitSet
getBitmap() {
	return bitmap;
}

byte []
rrToWire() throws IOException {
	if (next == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	DataOutputStream ds = new DataOutputStream(bs);

	next.toWire(ds);
	for (int i = 0, t = 0; i < bitmap.size(); i++) {
		t |= (bitmap.get(i) ? (1 << (7 - i % 8)) : 0);
		if (i % 8 == 7 || i == bitmap.size() - 1) {
			ds.writeByte(t);
			t = 0;
		}
	}
	return bs.toByteArray();
}

}

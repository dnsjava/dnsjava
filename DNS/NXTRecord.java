// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class NXTRecord extends Record {

Name next;
BitSet bitmap;

public
NXTRecord(Name _name, short _dclass, int _ttl, Name _next, BitSet _bitmap) {
	super(_name, Type.NXT, _dclass, _ttl);
	next = _next;
	bitmap = _bitmap;
}

public
NXTRecord(Name _name, short _dclass, int _ttl,
	  int length, CountedDataInputStream in, Compression c)
throws IOException
{
	super(_name, Type.NXT, _dclass, _ttl);
	if (in == null)
		return;
	int start = in.getPos();
	next = new Name(in, c);
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
NXTRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.NXT, _dclass, _ttl);
	Vector types = new Vector();
	next = new Name(st.nextToken(), origin);
	bitmap = new BitSet();
	while (st.hasMoreTokens()) {
		short t = Type.value(st.nextToken());
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
				sb.append(Type.string(i));
			}
	}
	return sb.toString();
}

public Name
getNext() {
	return next;
}

public BitSet
getBitmap() {
	return bitmap;
}

byte []
rrToWire(Compression c, int index) throws IOException {
	if (next == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	next.toWire(ds, null);
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

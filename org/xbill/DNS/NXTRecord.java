// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Next name - this record contains the following name in an ordered list
 * of names in the zone, and a set of types for which records exist for
 * this name.  The presence of this record in a response signifies a
 * failed query for data in a DNSSEC-signed zone. 
 *
 * @author Brian Wellington
 */

public class NXTRecord extends Record {

private static NXTRecord member = new NXTRecord();

private Name next;
private BitSet bitmap;

private
NXTRecord() {}

private
NXTRecord(Name name, short dclass, int ttl) {
	super(name, Type.NXT, dclass, ttl);
}

static NXTRecord
getMember() {
	return member;
}

/**
 * Creates an NXT Record from the given data
 * @param next The following name in an ordered list of the zone
 * @param bitmap The set of type for which records exist at this name
*/
public
NXTRecord(Name name, short dclass, int ttl, Name next, BitSet bitmap) {
	this(name, dclass, ttl);
	this.next = next;
	this.bitmap = bitmap;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	NXTRecord rec = new NXTRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	int start = in.getPos();
	rec.next = new Name(in);
	rec.bitmap = new BitSet();
	int bitmapLength = length - (in.getPos() - start);
	for (int i = 0; i < bitmapLength; i++) {
		int t = in.readUnsignedByte();
		for (int j = 0; j < 8; j++)
			if ((t & (1 << (7 - j))) != 0)
				rec.bitmap.set(i * 8 + j);
	}
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	NXTRecord rec = new NXTRecord(name, dclass, ttl);
	rec.next = Name.fromString(nextString(st), origin);
	rec.next.checkAbsolute("read an NXT record");
	rec.bitmap = new BitSet();
	while (st.hasMoreTokens()) {
		short t = Type.value(nextString(st));
		if (t > 0)
			rec.bitmap.set(t);
	}
	return rec;
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (next != null) {
		sb.append(next);
		int length = BitSetLength(bitmap);
		for (short i = 0; i < length; i++)
			if (bitmap.get(i)) {
				sb.append(" ");
				sb.append(Type.string(i));
			}
	}
	return sb.toString();
}

/** Returns the next name */
public Name
getNext() {
	return next;
}

/** Returns the set of types defined for this name */
public BitSet
getBitmap() {
	return bitmap;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (next == null)
		return;

	next.toWire(out, null, canonical);
	int length = BitSetLength(bitmap);
	for (int i = 0, t = 0; i < length; i++) {
		t |= (bitmap.get(i) ? (1 << (7 - i % 8)) : 0);
		if (i % 8 == 7 || i == length - 1) {
			out.writeByte(t);
			t = 0;
		}
	}
}

private int
BitSetLength(BitSet b) {
	for (int i = b.size() - 1; i >= 0; i--)
		if (b.get(i))
			return i + 1;
	return (-1);
}

}

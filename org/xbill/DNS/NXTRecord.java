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

private Name next;
private BitSet bitmap;

private
NXTRecord() {}

/**
 * Creates an NXT Record from the given data
 * @param next The following name in an ordered list of the zone
 * @param bitmap The set of type for which records exist at this name
*/
public
NXTRecord(Name _name, short _dclass, int _ttl, Name _next, BitSet _bitmap) {
	super(_name, Type.NXT, _dclass, _ttl);
	next = _next;
	bitmap = _bitmap;
}

NXTRecord(Name _name, short _dclass, int _ttl, int length,
	  DataByteInputStream in, Compression c)
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

/** Converts to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
	if (next != null) {
		sb.append(next);
		int length = BitSetLength(bitmap);
		for (int i = 0; i < length; i++)
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (next == null)
		return;

	next.toWire(out, null);
	int length = BitSetLength(bitmap);
	for (int i = 0, t = 0; i < length; i++) {
		t |= (bitmap.get(i) ? (1 << (7 - i % 8)) : 0);
		if (i % 8 == 7 || i == length - 1) {
			out.writeByte(t);
			t = 0;
		}
	}
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	if (next == null)
		return;

	next.toWireCanonical(out);
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

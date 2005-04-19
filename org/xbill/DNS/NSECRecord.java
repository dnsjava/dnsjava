// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * Next SECure name - this record contains the following name in an
 * ordered list of names in the zone, and a set of types for which
 * records exist for this name.  The presence of this record in a response
 * signifies a negative response from a DNSSEC-signed zone.
 *
 * This replaces the NXT record.
 *
 * @author Brian Wellington
 * @author David Blacka
 */

public class NSECRecord extends Record {

private Name next;
private int types[];

NSECRecord() {}

Record
getObject() {
	return new NSECRecord();
}

/**
 * Creates an NSEC Record from the given data.
 * @param next The following name in an ordered list of the zone
 * @param types An array containing the types present.
 */
public
NSECRecord(Name name, int dclass, long ttl, Name next, int [] types) {
	super(name, Type.NSEC, dclass, ttl);
	this.next = checkName("next", next);
	for (int i = 0; i < types.length; i++) {
		Type.check(types[i]);
	}
	this.types = new int[types.length];
	System.arraycopy(types, 0, this.types, 0, types.length);
	Arrays.sort(this.types);
}

private int []
listToArray(List list) {
	int size = list.size();
	int [] array = new int[size];
	for (int i = 0; i < size; i++) {
		array[i] = ((Integer)list.get(i)).intValue();
	}
	return array;
}

void
rrFromWire(DNSInput in) throws IOException {
	next = new Name(in);

	int lastbase = -1;
	List list = new ArrayList();
	while (in.remaining() > 0) {
		if (in.remaining() < 2)
			throw new WireParseException
						("invalid bitmap descriptor");
		int mapbase = in.readU8();
		if (mapbase < lastbase)
			throw new WireParseException("invalid ordering");
		int maplength = in.readU8();
		if (maplength > in.remaining())
			throw new WireParseException("invalid bitmap");
		for (int i = 0; i < maplength; i++) {
			int current = in.readU8();
			if (current == 0)
				continue;
			for (int j = 0; j < 8; j++) {
				if ((current & (1 << (7 - j))) == 0)
					continue;
				int typecode = mapbase * 256 + + i * 8 + j;
				list.add(Mnemonic.toInteger(typecode));
			}
		}
	}
	types = listToArray(list);
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	next = st.getName(origin);
	List list = new ArrayList();
	while (true) {
		Tokenizer.Token t = st.get();
		if (!t.isString())
			break;
		int type = Type.value(t.value);
		if (type < 0) {
			throw st.exception("Invalid type: " + t.value);
		}
		list.add(Mnemonic.toInteger(type));
	}
	st.unget();
	types = listToArray(list);
	Arrays.sort(types);
}

/** Converts rdata to a String */
String
rrToString()
{
	StringBuffer sb = new StringBuffer();
	sb.append(next);
	for (int i = 0; i < types.length; i++) {
		sb.append(" ");
		sb.append(Type.string(types[i]));
	}
	return sb.toString();
}

/** Returns the next name */
public Name
getNext() {
	return next;
}

/** Returns the set of types defined for this name */
public int []
getTypes() {
	int [] array = new int[types.length];
	System.arraycopy(types, 0, array, 0, types.length);
	return array;
}

/** Returns whether a specific type is in the set of types. */
public boolean
hasType(int type) {
	return (Arrays.binarySearch(types, type) >= 0);
}

static void
mapToWire(DNSOutput out, int [] array, int mapbase,
	  int mapstart, int mapend)
{
	int mapmax = array[mapend - 1] & 0xFF;
	int maplength = (mapmax / 8) + 1;
	int [] map = new int[maplength];
	out.writeU8(mapbase);
	out.writeU8(maplength);
	for (int j = mapstart; j < mapend; j++) {
		int typecode = array[j];
		map[(typecode & 0xFF) / 8] |= (1 << ( 7 - typecode % 8));
	}
	for (int j = 0; j < maplength; j++) {
		out.writeU8(map[j]);
	}
}

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	next.toWire(out, null, canonical);

	if (types.length == 0)
		return;
	int mapbase = -1;
	int mapstart = -1;
	for (int i = 0; i < types.length; i++) {
		int base = types[i] >> 8;
		if (base == mapbase)
			continue;
		if (mapstart >= 0) {
			mapToWire(out, types, mapbase, mapstart, i);
		}
		mapbase = base;
		mapstart = i;
	}
	mapToWire(out, types, mapbase, mapstart, types.length);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * A representation of a bitstring label
 *
 * @author Brian Wellington
 */

class BitString {

int nbits;
byte [] data;

BitString(String s) throws IOException {
System.out.println("parsing BitString");
	if (s.length() < 5 || !s.startsWith("\\[") || !s.endsWith("]"))
		throw new IOException("Invalid binary label: " + s);
	int radix, bits;
	switch (s.charAt(2)) {
		case 'x': radix = 16; bits = 4; break;
		case 'o': radix = 8; bits = 3; break;
		case 'b': radix = 2; bits = 1; break;
		default: throw new IOException("Invalid binary label: " + s);
	}
	int i, j = 0;
	boolean slash = false;
	BitSet set = new BitSet();
		
	for (i = 3; i < s.length() - 1; i++, j++) {
		if (s.charAt(i) == '/') {
			slash = true;
			break;
		}
		int x = Character.digit(s.charAt(i), radix);
		if (x == -1)
			throw new IOException("Invalid binary label: " + s);
		switch (radix) {
			case 2:
				if (x == 1)
					set.set(j);
				nbits++;
				break;
			case 8:
				if ((x & 0x4) != 0)
					set.set(3 * j);
				if ((x & 0x2) != 0)
					set.set(3 * j + 1);
				if ((x & 0x1) != 0)
					set.set(3 * j + 2);
				nbits+=3;
				break;
			case 16:
				if ((x & 0x8) != 0)
					set.set(4 * j);
				if ((x & 0x4) != 0)
					set.set(4 * j + 1);
				if ((x & 0x2) != 0)
					set.set(4 * j + 2);
				if ((x & 0x1) != 0)
					set.set(4 * j + 3);
				nbits+=4;
				break;
		}
	}
	if (slash) {
		String count = s.substring(i + 1, s.length() - 1);
		try {
			int bitcount = Integer.parseInt(count);
			if (bitcount > nbits || bitcount < 0)
				throw new Exception();
			nbits = bitcount;
		}
		catch (Exception e) {
			throw new IOException("Invalid binary label: " + s);
		}
	}
	data = new byte[bytes()];
	for (i = 0; i < nbits; i++)
		data[i/8] |= ((set.get(i) ? 1 : 0) << (7 - i%8));
System.out.println("nbits = " + nbits);
}

BitString(int _nbits, byte [] _data) {
	nbits = _nbits;
	data = _data;
}

int
bytes() {
	return (nbits + 7) / 8;
}

int
wireBits() {
	return (nbits == 256 ? 0 : nbits);
}

public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append("\\[x");
	for (int i = 0; i < bytes(); i++) {
		int value = (int)(data[i] & 0xFF);
		int high = value >> 4;
		int low = value & 0xf;
		sb.append(Integer.toHexString(high));
		if (low > 0 || i < bytes() - 1)
			sb.append(Integer.toHexString(low));
	}
	sb.append("/");
	sb.append(nbits);
	sb.append("]");
	return sb.toString();
}

public boolean
equals(Object o) {
	if (!(o instanceof BitString))
		return false;
	BitString b = (BitString) o;
	if (nbits != b.nbits)
		return false;
	for (int i = 0; i < bytes(); i++)
		if (data[i] != b.data[i])
			return false;
	return true;
}

}

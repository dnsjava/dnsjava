// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS.utils;

import java.io.*;
import java.math.*;

public class DataByteOutputStream extends ByteArrayOutputStream {

public
DataByteOutputStream(int size) {
	super(size);
}

public
DataByteOutputStream() {
	super();
}

public void
writeByte(int i) {
	write(i);
}

public void
writeShort(int i) {
	write((i >>> 8) & 0xFF);
	write(i & 0xFF);
}

public void
writeInt(int i) {
	write((i >>> 24) & 0xFF);
	write((i >>> 16) & 0xFF);
	write((i >>> 8) & 0xFF);
	write(i & 0xFF);
}

public void
writeLong(long l) {
	write((int)(l >>> 56) & 0xFF);
	write((int)(l >>> 48) & 0xFF);
	write((int)(l >>> 40) & 0xFF);
	write((int)(l >>> 32) & 0xFF);
	write((int)(l >>> 24) & 0xFF);
	write((int)(l >>> 16) & 0xFF);
	write((int)(l >>> 8) & 0xFF);
	write((int)l & 0xFF);
}

public void
writeString(String s) {
	try {
		byte [] b = s.getBytes();
		write(b.length);
		write(b);
	}
	catch (IOException e) {
	}
}

public void
writeBigInteger(BigInteger i) {
	byte [] b = i.toByteArray();
	try {
		if (b[0] == 0)
			write(b, 1, b.length - 1);
		else
			write(b);
	}
	catch (IOException e) {
	}
}

public void
writeShortAt(int i, int pos) throws IllegalArgumentException {
	if (pos < 0 || pos > count)
		throw new IllegalArgumentException(pos + " out of range");
	int oldcount = count;
	count = pos;
	writeShort(i);
	count = oldcount;
}

public int
getPos() {
	return count;
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS.utils;

import java.io.*;
import java.math.BigInteger;

public class DataByteInputStream extends ByteArrayInputStream {

public
DataByteInputStream(byte [] b) {
	super(b);
}

public int
read(byte b[]) throws IOException {
	return read(b, 0, b.length);
}

public byte
readByte() throws IOException {
	return (byte) read();
}

public int
readUnsignedByte() throws IOException {
	return read();
}

public short
readShort() throws IOException {
	int c1 = read();
	int c2 = read();
	return (short)((c1 << 8) + c2);
}

public int
readUnsignedShort() throws IOException {
	int c1 = read();
	int c2 = read();
	return ((c1 << 8) + c2);
}

public int
readInt() throws IOException {
	int c1 = read();
	int c2 = read();
	int c3 = read();
	int c4 = read();
	return ((c1 << 24) + (c2 << 16) + (c3 << 8) + c4);
}

public long
readLong() throws IOException {
	int c1 = read();
	int c2 = read();
	int c3 = read();
	int c4 = read();
	int c5 = read();
	int c6 = read();
	int c7 = read();
	int c8 = read();
	return ((c1 << 56) + (c2 << 48) + (c3 << 40) + (c4 << 32) +
		(c5 << 24) + (c6 << 16) + (c7 << 8) + c8);
}

public String
readString() throws IOException {
	int len = read();
	byte [] b = new byte[len];
	read(b);
	return new String(b);
}

public BigInteger
readBigInteger(int len) throws IOException {
	byte [] b = new byte[len + 1];
	read(b, 1, len);
	return new BigInteger(b);
}

public void
skipBytes(int n) throws IOException {
	skip(n);
}

public int
getPos() {
	return pos;
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;
import java.math.BigInteger;

/**
 * An extension of ByteArrayInputStream to support directly reading types
 * used by DNS routines.
 * @see DataByteOutputStream
 *
 * @author Brian Wellington
 */

public class DataByteInputStream extends ByteArrayInputStream {

/**
 * Creates a new DataByteInputStream
 * @param b The byte array to read from
 */
public
DataByteInputStream(byte [] b) {
	super(b);
}

/**
 * Read data from the stream.
 * @param b The array to read into
 * @return The number of bytes read
 */
public int
read(byte [] b) throws IOException {
	int n = read(b, 0, b.length);
	if (n < b.length)
		throw new IOException("end of input");
	return n;
}

/**
 * Read data from the stream.
 * @param b The array to read into
 * @param pos The starting position
 * @param len The number of bytes to read
 * @return The number of bytes read
 */
public int
readArray(byte [] b, int pos, int len) throws IOException {
	int n = read(b, pos, len);
	if (n < len)
		throw new IOException("end of input");
	return n;
}

/**
 * Read a byte from the stream
 * @return The byte
 */
public byte
readByte() throws IOException {
	int i = read();
	if (i == -1)
		throw new IOException("end of input");
	return (byte) i;
}

/**
 * Read an unsigned byte from the stream
 * @return The unsigned byte as an int
 */
public int
readUnsignedByte() throws IOException {
	int i = read();
	if (i == -1)
		throw new IOException("end of input");
	return i;
}

/**
 * Read a short from the stream
 * @return The short
 */
public short
readShort() throws IOException {
	int c1 = read();
	int c2 = read();
	if (c1 == -1 || c2 == -1)
		throw new IOException("end of input");
	return (short)((c1 << 8) + c2);
}

/**
 * Read an unsigned short from the stream
 * @return The unsigned short as an int
 */
public int
readUnsignedShort() throws IOException {
	int c1 = read();
	int c2 = read();
	if (c1 == -1 || c2 == -1)
		throw new IOException("end of input");
	return ((c1 << 8) + c2);
}

/**
 * Read an int from the stream
 * @return The int
 */
public int
readInt() throws IOException {
	int c1 = read();
	int c2 = read();
	int c3 = read();
	int c4 = read();
	if (c1 == -1 || c2 == -1 || c3 == -1 || c4 == -1)
		throw new IOException("end of input");
	return ((c1 << 24) + (c2 << 16) + (c3 << 8) + c4);
}

/**
 * Read a long from the stream
 * @return The long
 */
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
	if (c1 == -1 || c2 == -1 || c3 == -1 || c4 == -1 ||
	    c5 == -1 || c6 == -1 || c7 == -1 || c8 == -1)
		throw new IOException("end of input");
	return ((c1 << 56) + (c2 << 48) + (c3 << 40) + (c4 << 32) +
		(c5 << 24) + (c6 << 16) + (c7 << 8) + c8);
}

/**
 * Read a String from the stream, represented as a length byte followed by data,
 * and encode it in a byte array.
 * @return The array
 */
public byte []
readStringIntoArray() throws IOException {
	int len = read();
	if (len == -1)
		throw new IOException("end of input");
	byte [] b = new byte[len];
	int n = read(b);
	if (n < len)
		throw new IOException("end of input");
	return b;
}

/**
 * Read a String from the stream, represented as a length byte followed by data
 * @return The String
 */
public String
readString() throws IOException {
	byte [] b = readStringIntoArray();
	return new String(b);
}


/**
 * Read a BigInteger from the stream, encoded as binary data.  A 0 byte is
 * prepended so that the value is always positive.
 * @param len The number of bytes to read
 * @return The BigInteger
 */
public BigInteger
readBigInteger(int len) throws IOException {
	byte [] b = new byte[len + 1];
	int n = read(b, 1, len);
	if (n < len)
		throw new IOException("end of input");
	return new BigInteger(b);
}

/**
 * Read and ignore bytes from the stream
 * @param n The number of bytes to skip
 */
public void
skipBytes(int n) throws IOException {
	skip(n);
}

/**
 * Get the current position in the stream
 * @return The current position
 */
public int
getPos() {
	return pos;
}

/**
 * Sets the current position in the stream
 */
public void
setPos(int pos) {
	this.pos = pos;
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;
import java.math.*;

/**
 * An extension of ByteArrayOutputStream to support directly writing types
 * used by DNS routines.
 * @see DataByteInputStream
 *
 * @author Brian Wellington
 */


public class DataByteOutputStream extends ByteArrayOutputStream {

/**
 * Create a new DataByteOutputStream with a specified initial size
 * @param size The initial size
 */
public
DataByteOutputStream(int size) {
	super(size);
}

/**
 * Create a new DataByteOutputStream with the default initial size
 * @param size The initial size
 */
public
DataByteOutputStream() {
	super();
}

/**
 * Writes a byte to the stream
 * @param i The byte to be written
 */
public void
writeByte(int i) {
	write(i);
}

/**
 * Writes a short to the stream
 * @param i The short to be written
 */
public void
writeShort(int i) {
	write((i >>> 8) & 0xFF);
	write(i & 0xFF);
}

/**
 * Writes an int to the stream
 * @param i The int to be written
 */
public void
writeInt(int i) {
	write((i >>> 24) & 0xFF);
	write((i >>> 16) & 0xFF);
	write((i >>> 8) & 0xFF);
	write(i & 0xFF);
}

/**
 * Writes a long to the stream
 * @param l The long to be written
 */
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

/**
 * Writes a String to the stream, encoded as a length byte followed by data
 * @param s The String to be written
 */
public void
writeString(String s) {
	writeByte(s.length());
	writeArray(s.getBytes());
}

/**
 * Writes a string represented by a byte array to the stream, encoded as a
 * length byte followed by data
 * @param s The byte array containing the string to be written
 * @param start The start of the string withing the byte array.
 */
public void
writeString(byte [] s, int start) {
	write(s, start, s[start] + 1);
}

/**
 * Writes a full byte array to the stream.
 * @param b The byte array to be written.
 */
public void
writeArray(byte [] b, boolean writeLength) {
	if (writeLength)
		writeByte(b.length);
	write(b, 0, b.length);
}

/**
 * Writes a full byte array to the stream.
 * @param b The byte array to be written.
 */
public void
writeArray(byte [] b) {
	write(b, 0, b.length);
}

/**
 * Writes a BigInteger to the stream, encoded as binary data.  If present,
 * the leading 0 byte is removed.
 * @param i The BigInteger to be written
 */
public void
writeBigInteger(BigInteger i) {
	byte [] b = i.toByteArray();
	if (b[0] == 0)
		write(b, 1, b.length - 1);
	else
		write(b, 0, b.length);
}

/**
 * Writes a short to the stream at a specific location
 * @param i The short to be written
 * @param pos The position at which the write occurs
 */
public void
writeShortAt(int i, int pos) throws IllegalArgumentException {
	if (pos < 0 || pos > count)
		throw new IllegalArgumentException(pos + " out of range");
	int oldcount = count;
	count = pos;
	writeShort(i);
	count = oldcount;
}

/**
 * Set the current position in the stream
 * @param pos The current position
 */
public void
setPos(int pos) {
	count = pos;
}

/**
 * Get the current position in the stream
 * @return The current position
 */
public int
getPos() {
	return count;
}

}

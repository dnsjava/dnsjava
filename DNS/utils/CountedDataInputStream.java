// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.InputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class CountedDataInputStream {

int counter;
DataInputStream in;

public
CountedDataInputStream(InputStream i) {
	in = new DataInputStream(i);
	counter = 0;
}

int
read(byte b[]) throws IOException {
	in.readFully(b);
	int out = b.length;
	if (out >= 0)
		counter += out;
	return out;
}

byte
readByte() throws IOException {
	counter += 1;
	return in.readByte();
}

int
readUnsignedByte() throws IOException {
	counter += 1;
	return in.readUnsignedByte();
}

short
readShort() throws IOException {
	counter += 2;
	return in.readShort();
}

int
readUnsignedShort() throws IOException {
	counter += 2;
	return in.readUnsignedShort();
}

int
readInt() throws IOException {
	counter += 4;
	return in.readInt();
}

long
readLong() throws IOException {
	counter += 8;
	return in.readLong();
}

String
readString() throws IOException {
	int len = in.readByte();
	counter++;
	byte [] b = new byte[len];
	in.readFully(b);
	counter+=len;
	return new String(b);
}

int
skipBytes(int n) throws IOException {
	counter += n;
	return in.skipBytes(n);
}

int
getPos() {
	return counter;
}

}

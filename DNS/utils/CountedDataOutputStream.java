// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.OutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class CountedDataOutputStream {

int counter;
DataOutputStream out;

public
CountedDataOutputStream(OutputStream o) {
	out = new DataOutputStream(o);
	counter = 0;
}

void
write(byte b[]) throws IOException {
	out.write(b);
	counter += b.length;
}

void
writeByte(int i) throws IOException {
	counter += 1;
	out.writeByte((byte)i);
}

void
writeShort(int i) throws IOException {
	counter += 2;
	out.writeShort((short)i);
}

void
writeInt(int i) throws IOException {
	counter += 4;
	out.writeInt(i);
}

void
writeLong(long l) throws IOException {
	counter += 8;
	out.writeLong(l);
}

void
writeString(String s) throws IOException {
	byte [] b = s.getBytes();
	out.writeByte(b.length);
	out.write(b);
	counter += (1 + b.length);
}

int
getPos() {
	return counter;
}

}

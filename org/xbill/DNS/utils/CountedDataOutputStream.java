// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS.utils;

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

public void
write(byte b[]) throws IOException {
	out.write(b);
	counter += b.length;
}

public void
write(byte b[], int offset, int length) throws IOException {
	out.write(b, offset, length);
	counter += length;
}

public void
writeByte(int i) throws IOException {
	counter += 1;
	out.writeByte((byte)i);
}

public void
writeShort(int i) throws IOException {
	counter += 2;
	out.writeShort((short)i);
}

public void
writeInt(int i) throws IOException {
	counter += 4;
	out.writeInt(i);
}

public void
writeLong(long l) throws IOException {
	counter += 8;
	out.writeLong(l);
}

public void
writeString(String s) throws IOException {
	byte [] b = s.getBytes();
	out.writeByte(b.length);
	out.write(b);
	counter += (1 + b.length);
}

public int
getPos() {
	return counter;
}

}

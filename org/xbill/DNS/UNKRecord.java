// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * A class implementing Records of unknown and/or unimplemented types.  This
 * class can only be initialized using static Record initializers.
 *
 * @author Brian Wellington
 */

public class UNKRecord extends Record {

private byte [] data;

UNKRecord() {}

Record
getObject() {
	return new UNKRecord();
}

void
rrFromWire(DNSInput in) throws IOException {
	data = in.readByteArray();
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	throw st.exception("invalid unknown RR encoding");
}

/** Converts this Record to the String "unknown format" */
String
rrToString() {
	StringBuffer sb = new StringBuffer();
	sb.append("\\# ");
	sb.append(data.length);
	sb.append(" ");
	sb.append(base16.toString(data));
	return sb.toString();
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (data != null)
		out.writeArray(data);
}

}

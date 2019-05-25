// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;

/**
 * A class implementing Records with no data; that is, records used in
 * the question section of messages and meta-records in dynamic update.
 *
 * @author Brian Wellington
 */

class EmptyRecord extends Record {

private static final long serialVersionUID = 3601852050646429582L;

EmptyRecord() {}

@Override
Record
getObject() {
	return new EmptyRecord();
}

@Override
void
rrFromWire(DNSInput in) throws IOException {
}

@Override
void
rdataFromString(Tokenizer st, Name origin) throws IOException {
}

@Override
String
rrToString() {
	return "";
}

@Override
void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
}

}

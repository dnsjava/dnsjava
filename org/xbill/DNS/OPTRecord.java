// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class OPTRecord extends Record {

public
OPTRecord(Name _name, short _dclass, int _ttl) {
	super(_name, Type.OPT, _dclass, _ttl);
}

public
OPTRecord(Name _name, short _dclass, int _ttl,
	  int length, CountedDataInputStream in, Compression c)
throws IOException
{
	super(_name, Type.OPT, _dclass, _ttl);
	if (in == null)
		return;
	/* for now, skip the rest */
}

public String
toString() {
	StringBuffer sb = toStringNoData();
	return sb.toString();
}

public short
getPayloadSize() {
	return dclass;
}

public short
getExtendedRcode() {
	return (short) (ttl >>> 24);
}

public short
getVersion() {
	return (short) ((ttl >>> 16) & 0xFF);
}

byte []
rrToWire(Compression c, int index) throws IOException {
	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs);

	/* probably should dump bytes in here */
	return bs.toByteArray();
}

}

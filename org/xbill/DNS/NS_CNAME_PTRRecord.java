// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class NS_CNAME_PTRRecord extends Record {

Name target;

public
NS_CNAME_PTRRecord(Name _name, short _type, short _dclass, int _ttl,
		   Name _target)
{
	super(_name, _type, _dclass, _ttl);
	target = _target;
}

public
NS_CNAME_PTRRecord(Name _name, short _type, short _dclass, int _ttl,
		   int length, CountedDataInputStream in, Compression c)
throws IOException
{
	super(_name, _type, _dclass, _ttl);
	if (in == null)
		return;
	target = new Name(in, c);
}

public
NS_CNAME_PTRRecord(Name _name, short _type, short _dclass, int _ttl,
		   MyStringTokenizer st, Name origin)
throws IOException
{
        super(_name, _type, _dclass, _ttl);
        target = new Name(st.nextToken(), origin);
}


public String
toString() {
	StringBuffer sb = toStringNoData();
	if (target != null)
		sb.append(target);
	return sb.toString();
}

public Name
getTarget() {
	return target;
}

byte []
rrToWire(Compression c, int index) throws IOException {
	if (target == null)
		return null;

	ByteArrayOutputStream bs = new ByteArrayOutputStream();
	CountedDataOutputStream ds = new CountedDataOutputStream(bs, index);

	target.toWire(ds, c);
	return bs.toByteArray();
}

}

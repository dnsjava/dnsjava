// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;
import DNS.utils.*;

public class NSRecord extends NS_CNAME_PTRRecord {

public
NSRecord(Name _name, short _dclass, int _ttl, Name _target)
throws IOException
{
        super(_name, Type.NS, _dclass, _ttl, _target);
}

public
NSRecord(Name _name, short _dclass, int _ttl, int length,
	    CountedDataInputStream in, Compression c) throws IOException
{
	super(_name, Type.NS, _dclass, _ttl, length, in, c);
}

public
NSRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.NS, _dclass, _ttl, st, origin);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Name Server Record  - contains the name server serving the named zone
 *
 * @author Brian Wellington
 */

public class NSRecord extends NS_CNAME_PTRRecord {

private
NSRecord() {}

/** 
 * Creates a new NS Record with the given data
 * @param target The name server for the given domain
 */
public
NSRecord(Name _name, short _dclass, int _ttl, Name _target)
throws IOException
{
        super(_name, Type.NS, _dclass, _ttl, _target);
}

NSRecord(Name _name, short _dclass, int _ttl, int length,
	    DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.NS, _dclass, _ttl, length, in, c);
}

NSRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.NS, _dclass, _ttl, st, origin);
}

}

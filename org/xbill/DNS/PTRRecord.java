// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Pointer Record  - maps a domain name representing an Internet Address to
 * a hostname.
 *
 * @author Brian Wellington
 */

public class PTRRecord extends NS_CNAME_PTRRecord {

private
PTRRecord() {}

/** 
 * Creates a new PTR Record with the given data
 * @param target The name of the machine with this address
 */
public
PTRRecord(Name _name, short _dclass, int _ttl, Name _target)
throws IOException
{
        super(_name, Type.PTR, _dclass, _ttl, _target);
}

PTRRecord(Name _name, short _dclass, int _ttl, int length,
	  DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.PTR, _dclass, _ttl, length, in, c);
}

PTRRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
        super(_name, Type.PTR, _dclass, _ttl, st, origin);
}

}

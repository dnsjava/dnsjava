// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * CNAME Record  - maps an alias to its real name
 *
 * @author Brian Wellington
 */

public class CNAMERecord extends NS_CNAME_PTRRecord {

private
CNAMERecord() {}

/**
 * Creates a new CNAMERecord with the given data
 * @param target The name to which the CNAME alias points
 */
public
CNAMERecord(Name _name, short _dclass, int _ttl, Name _target)
throws IOException
{
        super(_name, Type.CNAME, _dclass, _ttl, _target);
}

CNAMERecord(Name _name, short _dclass, int _ttl, int length,
	    DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.CNAME, _dclass, _ttl, length, in, c);
}

CNAMERecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	       Name origin)
throws IOException
{
	super(_name, Type.CNAME, _dclass, _ttl, st, origin);
}

}

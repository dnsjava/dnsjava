// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * DNAME Record  - maps a nonterminal alias (subtree) to a different domain
 *
 * @author Brian Wellington
 */

public class DNAMERecord extends NS_CNAME_PTRRecord {

private
DNAMERecord() {}

/**
 * Creates a new DNAMERecord with the given data
 * @param target The name to which the DNAME alias points
 */
public
DNAMERecord(Name _name, short _dclass, int _ttl, Name _target)
throws IOException
{
        super(_name, Type.DNAME, _dclass, _ttl, _target);
}

DNAMERecord(Name _name, short _dclass, int _ttl, int length,
	    DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.DNAME, _dclass, _ttl, length, in, c);
}

DNAMERecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	       Name origin)
throws IOException
{
	super(_name, Type.DNAME, _dclass, _ttl, st, origin);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.util.*;

public class dnsCNAMERecord extends dnsNS_CNAME_PTRRecord {

public
dnsCNAMERecord(dnsName _name, short _dclass, int _ttl, dnsName _target)
throws IOException
{
        super(_name, dns.CNAME, _dclass, _ttl, _target);
}

public
dnsCNAMERecord(dnsName _name, short _dclass, int _ttl, int length,
	       CountedDataInputStream in, dnsCompression c) throws IOException
{
	super(_name, dns.CNAME, _dclass, _ttl, length, in, c);
}

public
dnsCNAMERecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st,
	       dnsName origin)
throws IOException
{
	super(_name, dns.CNAME, _dclass, _ttl, st, origin);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsNSRecord extends dnsNS_CNAME_PTRRecord {

public
dnsNSRecord(dnsName _name, short _dclass, int _ttl, dnsName _target)
throws IOException
{
        super(_name, dns.NS, _dclass, _ttl, _target);
}

public
dnsNSRecord(dnsName _name, short _dclass, int _ttl, int length,
	    CountedDataInputStream in, dnsCompression c) throws IOException
{
	super(_name, dns.NS, _dclass, _ttl, length, in, c);
}

public
dnsNSRecord(dnsName _name, short _dclass, int _ttl, MyStringTokenizer st)
throws IOException
{
	super(_name, dns.NS, _dclass, _ttl, st);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

import java.io.*;
import java.util.*;

public class dnsPTRRecord extends dnsNS_CNAME_PTRRecord {

public
dnsPTRRecord(dnsName _name, short _dclass, int _ttl, dnsName _target)
throws IOException
{
        super(_name, dns.PTR, _dclass, _ttl, _target);
}

public
dnsPTRRecord(dnsName _name, short _dclass, int _ttl, int length,
	     CountedDataInputStream in, dnsCompression c) throws IOException
{
	super(_name, dns.PTR, _dclass, _ttl, length, in, c);
}

public
dnsPTRRecord(dnsName _name, short _dclass, int _ttl, StringTokenizer st)
throws IOException
{
        super(_name, dns.PTR, _dclass, _ttl, st);
}

}

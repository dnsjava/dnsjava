// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

public class dnsNSRecord extends dnsNS_CNAME_PTR_Record {

public dnsNSRecord(dnsName rname, short rclass) {
	super(rname, dns.NS, rclass);
}

public dnsNSRecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.NS, rclass, rttl, name);
}

}

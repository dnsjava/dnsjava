// Copyright (c) 1999 Brian Wellington (bwelling@anomaly.munge.com)
// Portions Copyright (c) 1999 Network Associates, Inc.

public class dnsCNAMERecord extends dnsNS_CNAME_PTR_Record {

public dnsCNAMERecord(dnsName rname, short rclass) {
	super(rname, dns.CNAME, rclass);
}

public dnsCNAMERecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.CNAME, rclass, rttl, name);
}

}

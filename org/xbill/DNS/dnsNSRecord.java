public class dnsNSRecord extends dnsNS_CNAME_MX_Record {

public dnsNSRecord(dnsName rname, short rclass) {
	super(rname, dns.NS, rclass);
}

public dnsNSRecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.NS, rclass, rttl, name);
}

}

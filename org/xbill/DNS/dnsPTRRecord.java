public class dnsPTRRecord extends dnsNS_CNAME_MX_Record {

dnsPTRRecord(dnsName rname, short rclass) {
	super(rname, dns.PTR, rclass);
}

dnsPTRRecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.PTR, rclass, rttl, name);
}

}

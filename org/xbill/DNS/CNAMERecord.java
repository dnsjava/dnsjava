public class dnsCNAMERecord extends dnsNS_CNAME_MX_Record {

dnsCNAMERecord(dnsName rname, short rclass) {
	super(rname, dns.CNAME, rclass);
}

dnsCNAMERecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.CNAME, rclass, rttl, name);
}

}

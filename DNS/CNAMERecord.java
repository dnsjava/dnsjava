public class dnsCNAMERecord extends dnsNS_CNAME_MX_Record {

public dnsCNAMERecord(dnsName rname, short rclass) {
	super(rname, dns.CNAME, rclass);
}

public dnsCNAMERecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.CNAME, rclass, rttl, name);
}

}

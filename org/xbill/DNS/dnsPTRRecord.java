public class dnsPTRRecord extends dnsNS_CNAME_PTR_Record {

public dnsPTRRecord(dnsName rname, short rclass) {
	super(rname, dns.PTR, rclass);
}

public dnsPTRRecord(dnsName rname, short rclass, int rttl, dnsName name) {
	super(rname, dns.PTR, rclass, rttl, name);
}

}

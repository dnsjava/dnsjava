public class dnsEDNS {

public static dnsOPTRecord
newOPT(int payloadSize) {
	return new dnsOPTRecord(dnsName.root, (short)payloadSize, 0);
}

}


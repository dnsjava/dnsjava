// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

public class dnsEDNS {

public static dnsOPTRecord
newOPT(int payloadSize) {
	return new dnsOPTRecord(dnsName.root, (short)payloadSize, 0);
}

}


// Copyright (c) 2008 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.base64;

/**
 * DHCID - Dynamic Host Configuration Protocol (DHCP) ID (RFC 4701)
 *
 * @author Brian Wellington
 */

public class DHCIDRecord extends Record {

private static final long serialVersionUID = -8214820200808997707L;

private byte [] data;

DHCIDRecord() {}

@Override
Record
getObject() {
	return new DHCIDRecord();
}

/**
 * Creates an DHCID Record from the given data
 * @param data The binary data, which is opaque to DNS.
 */
public
DHCIDRecord(Name name, int dclass, long ttl, byte [] data) {
	super(name, Type.DHCID, dclass, ttl);
	this.data = data;
}

@Override
void
rrFromWire(DNSInput in) throws IOException {
	data = in.readByteArray();
}

@Override
void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	data = st.getBase64();
}

@Override
void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeByteArray(data);
}

@Override
String
rrToString() {
	return base64.toString(data);
}

/**
 * Returns the binary data.
 */
public byte []
getData() {
	return data;
}

}

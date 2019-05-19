package org.xbill.DNS;

import java.io.IOException;


/**
 * An abstract base class that is used to reduce duplicate code for different
 * DNSKEY record types.
 *
 * @author Brian Wellington
 * @author Dennis Reichenberg
 * @see    DNSKEYRecord
 * @see    CDNSKEYRecord
 */
public abstract class DNSKEYRecordBase extends KEYBase {

static private final long serialVersionUID = 439608609035127006L;

public DNSKEYRecordBase() {}

public DNSKEYRecordBase(Name name, int type,
						int dclass, long ttl,
						int flags, int proto, int alg,
						byte[] key) {
	super(name, type, dclass, ttl, flags, proto, alg, key);
}

void
rdataFromString(Tokenizer st, Name origin)
			  throws IOException {
	flags = st.getUInt16();
	proto = st.getUInt8();

	final String algString = st.getString();
	alg = DNSSEC.Algorithm.value(algString);

	if (alg < 0)
	{
		throw st.exception("Invalid algorithm: " + algString);
	}

	key = st.getBase64();
}
}

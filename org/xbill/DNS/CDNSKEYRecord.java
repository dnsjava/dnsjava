package org.xbill.DNS;

import java.io.IOException;
import java.security.PublicKey;

/**
 * Equivalent to {@link DNSKEYRecord}, but it is added to the child zone instead of the parent zone.
 */
public class CDNSKEYRecord extends KEYBase {

CDNSKEYRecord() {}

Record
getObject() {
    return new DNSKEYRecord();
}

/**
 * Creates a CNDSKEY Record from the given data
 * @param flags Flags describing the key's properties
 * @param proto The protocol that the key was created for
 * @param alg The key's algorithm
 * @param key Binary representation of the key
 */
public
CDNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg,
             byte [] key)
{
    super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, key);
}

/**
 * Creates a CNDSKEY Record from the given data
 * @param flags Flags describing the key's properties
 * @param proto The protocol that the key was created for
 * @param alg The key's algorithm
 * @param key The key as a PublicKey
 * @throws DNSSEC.DNSSECException The PublicKey could not be converted into DNS
 * format.
 */
public
CDNSKEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg,
             PublicKey key) throws DNSSEC.DNSSECException
{
    super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg,
            DNSSEC.fromPublicKey(key, alg));
    publicKey = key;
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
    flags = st.getUInt16();
    proto = st.getUInt8();
    String algString = st.getString();
    alg = DNSSEC.Algorithm.value(algString);
    if (alg < 0)
        throw st.exception("Invalid algorithm: " + algString);
    key = st.getBase64();
}
}

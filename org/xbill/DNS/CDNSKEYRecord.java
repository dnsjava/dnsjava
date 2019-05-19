package org.xbill.DNS;

import java.security.PublicKey;


/**
 * Equivalent to {@link DNSKEYRecord}, but it is added to the child zone instead
 * of the parent zone.
 */
public
class CDNSKEYRecord extends DNSKEYRecordBase
{
	static private final long serialVersionUID = 8018121023082348677L;

	/**
	 * Creates a CNDSKEY Record from the given data
	 *
	 * @param flags Flags describing the key's properties
	 * @param proto The protocol that the key was created for
	 * @param alg   The key's algorithm
	 * @param key   Binary representation of the key
	 */
	public CDNSKEYRecord(final Name name, final int dclass, final long ttl,
	                     final int flags, final int proto, final int alg,
	                     final byte[] key)
	{
		super(name, Type.CDNSKEY, dclass, ttl, flags, proto, alg, key);
	}

	/**
	 * Creates a CNDSKEY Record from the given data
	 *
	 * @param  flags Flags describing the key's properties
	 * @param  proto The protocol that the key was created for
	 * @param  alg   The key's algorithm
	 * @param  key   The key as a PublicKey
	 *
	 * @throws DNSSEC.DNSSECException The PublicKey could not be converted into
	 *                                DNS format.
	 */
	public CDNSKEYRecord(final Name name, final int dclass, final long ttl,
	                     final int flags, final int proto, final int alg,
	                     final PublicKey key) throws DNSSEC.DNSSECException
	{
		super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, DNSSEC.fromPublicKey(key, alg));
		publicKey = key;
	}

	CDNSKEYRecord()
	{
	}

	Record getObject()
	{
		return new CDNSKEYRecord();
	}
}

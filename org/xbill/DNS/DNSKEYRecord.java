// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.security.PublicKey;


/********************************************************************
 * Key - contains a cryptographic public key for use by DNS. The data can be
 * converted to objects implementing java.security.interfaces.PublicKey
 *
 * @see    DNSSEC
 * @author Brian Wellington
 */

public
class DNSKEYRecord extends AbstractDNSKEYRecord
{
	static private final long serialVersionUID = -8679800040426675002L;

	/***************************************
	 * Creates a DNSKEY Record from the given data
	 *
	 * @param flags Flags describing the key's properties
	 * @param proto The protocol that the key was created for
	 * @param alg   The key's algorithm
	 * @param key   Binary representation of the key
	 */
	public DNSKEYRecord(final Name name, final int dclass, final long ttl,
	                    final int flags, final int proto, final int alg,
	                    final byte[] key)
	{
		super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, key);
	}

	/***************************************
	 * Creates a DNSKEY Record from the given data
	 *
	 * @param  flags Flags describing the key's properties
	 * @param  proto The protocol that the key was created for
	 * @param  alg   The key's algorithm
	 * @param  key   The key as a PublicKey
	 *
	 * @throws DNSSEC.DNSSECException The PublicKey could not be converted into
	 *                                DNS format.
	 */
	public DNSKEYRecord(final Name name, final int dclass, final long ttl,
	                    final int flags, final int proto, final int alg,
	                    final PublicKey key) throws DNSSEC.DNSSECException
	{
		super(name, Type.DNSKEY, dclass, ttl, flags, proto, alg, DNSSEC.fromPublicKey(key, alg));
		publicKey = key;
	}

	DNSKEYRecord()
	{
	}

	@Override
	Record getObject()
	{
		return new DNSKEYRecord();
	}

	static public
	class Flags
	{
		/** Key is a zone key */
		static public final int ZONE_KEY = 0x100;

		/** Key is a secure entry point key */
		static public final int SEP_KEY = 0x1;

		/** Key has been revoked */
		static public final int REVOKE = 0x80;

		private Flags()
		{
		}
	}

	static public
	class Protocol
	{
		/** Key will be used for DNSSEC */
		static public final int DNSSEC = 3;

		private Protocol()
		{
		}
	}
}

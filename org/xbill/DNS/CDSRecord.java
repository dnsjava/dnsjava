package org.xbill.DNS;

/**
 * Equivalent to the {@link DSRecord}, but it is added to the child zone instead
 * of the parent zone.
 */
public
class CDSRecord extends DSRecordBase
{
	static private final long serialVersionUID = 1886725731593276503L;

	/**
	 * Creates a CDS Record from the given data
	 *
	 * @param digestid The digest id code.
	 * @param key      The key to digest
	 */
	public CDSRecord(final Name name, final int dclass, final long ttl,
	                 final int digestid, final DNSKEYRecord key)
	{
		this(name, dclass, ttl, key.getFootprint(), key.getAlgorithm(), digestid, DNSSEC.generateDSDigest(key, digestid));
	}

	/**
	 * Creates a CDS Record from the given data
	 *
	 * @param footprint The original KEY record's footprint (keyid).
	 * @param alg       The original key algorithm.
	 * @param digestid  The digest id code.
	 * @param digest    A hash of the original key.
	 */
	public CDSRecord(final Name name, final int dclass, final long ttl,
	                 final int footprint, final int alg, final int digestid,
	                 final byte[] digest)
	{
		super(name, Type.CDS, dclass, ttl, footprint, alg, digestid, digest);
	}

	CDSRecord()
	{
	}

	Record getObject()
	{
		return new CDSRecord();
	}
}

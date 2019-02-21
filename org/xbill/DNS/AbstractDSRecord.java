package org.xbill.DNS;

import org.xbill.DNS.utils.base16;

import java.io.IOException;


/********************************************************************
 * An abstract base class that is used to reduce duplicate code between the
 * different DS record types.
 *
 * @author Dennis Reichenberg
 * @see    DSRecord
 * @see    CDSRecord
 */
public abstract
class AbstractDSRecord extends Record
{
	static private final long serialVersionUID = -6303497472951402748L;
	private int               footprint;
	private int               alg;
	private int               digestid;
	private byte[]            digest;

	public AbstractDSRecord(final Name name, final int type, final int dclass,
	                        final long ttl, final int footprint, final int alg,
	                        final int digestid, final byte[] digest)
	{
		super(name, type, dclass, ttl);
		this.footprint = checkU16("footprint", footprint);
		this.alg       = checkU8("alg", alg);
		this.digestid  = checkU8("digestid", digestid);
		this.digest    = digest;
	}

	AbstractDSRecord()
	{
	}

	/***************************************
	 * Returns the key's algorithm.
	 */
	public int getAlgorithm()
	{
		return alg;
	}

	/***************************************
	 * Returns the binary hash of the key.
	 */
	public byte[] getDigest()
	{
		return digest;
	}

	/***************************************
	 * Returns the key's Digest ID.
	 */
	public int getDigestID()
	{
		return digestid;
	}

	/***************************************
	 * Returns the key's footprint.
	 */
	public int getFootprint()
	{
		return footprint;
	}

	@Override
	void rdataFromString(final Tokenizer st, final Name origin)
	              throws IOException
	{
		footprint = st.getUInt16();
		alg       = st.getUInt8();
		digestid  = st.getUInt8();
		digest    = st.getHex();
	}

	@Override
	void rrFromWire(final DNSInput in) throws IOException
	{
		footprint = in.readU16();
		alg       = in.readU8();
		digestid  = in.readU8();
		digest    = in.readByteArray();
	}

	/***************************************
	 * Converts rdata to a String
	 */
	@Override
	String rrToString()
	{
		final StringBuffer sb = new StringBuffer();
		sb.append(footprint);
		sb.append(" ");
		sb.append(alg);
		sb.append(" ");
		sb.append(digestid);

		if (digest != null)
		{
			sb.append(" ");
			sb.append(base16.toString(digest));
		}

		return sb.toString();
	}

	@Override
	void rrToWire(final DNSOutput out, final Compression c,
	              final boolean canonical)
	{
		out.writeU16(footprint);
		out.writeU8(alg);
		out.writeU8(digestid);

		if (digest != null)
		{
			out.writeByteArray(digest);
		}
	}
}

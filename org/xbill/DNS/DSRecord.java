// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * DS - contains a Delegation Signer record, which acts as a
 * placeholder for KEY records in the parent zone.
 * @see DNSSEC
 *
 * @author David Blacka
 * @author Brian Wellington
 */

public class DSRecord extends Record {

public static final byte SHA1_DIGEST_ID = 1;

private static DSRecord member = new DSRecord();

private int footprint;
private int alg;
private int digestid;
private byte [] digest;

private DSRecord() {}

private
DSRecord(Name name, int dclass, int ttl) {
	super(name, Type.DS, dclass, ttl);
}

static DSRecord
getMember() {
	return member;
}

/**
 * Creates a DS Record from the given data
 * @param footprint The original KEY record's footprint (keyid).
 * @param alg The original key algorithm.
 * @param digestid The digest id code.
 * @param digest A hash of the original key.
 */
public
DSRecord(Name name, int dclass, int ttl, int footprint, int alg,
	 int digestid, byte []  digest)
{
	this(name, dclass, ttl);
	if (footprint < 0 || footprint > 0xFFFF)
		throw new IllegalArgumentException("invalid footprint: " +
						   footprint);
	if (alg < 0 || alg > 0xFF)
		throw new IllegalArgumentException("invalid algorithm: " +
						   alg);
	if (digestid < 0 || digestid > 0xFF)
		throw new IllegalArgumentException("invalid digest id: " +
						   digestid);
	this.footprint = footprint;
	this.alg = alg;
	this.digestid = digestid;
	this.digest = digest;
}

Record
rrFromWire(Name name, int type, int dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	DSRecord rec = new DSRecord(name, dclass, ttl);
	if (in == null)
		return rec;

	rec.footprint = in.readUnsignedShort();
	rec.alg = in.readUnsignedByte();
	rec.digestid = in.readUnsignedByte();

	if (length > 4) {
		rec.digest = new byte[length - 4];
		in.read(rec.digest);
	}
	return rec;
}

Record
rdataFromString(Name name, int dclass, int ttl, Tokenizer st, Name origin)
throws IOException
{
	DSRecord rec = new DSRecord(name, dclass, ttl);
	rec.footprint = st.getUInt16();
	rec.alg = (byte) st.getUInt8();
	rec.digestid = (byte) st.getUInt8();

	// note that the draft says that the digest is presented as hex,
	// not base64.
	rec.digest = base16.fromString(remainingStrings(st));
	return rec;
}

/**
 * Converts rdata to a String
 */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	sb.append(footprint);
	sb.append(" ");
	sb.append(alg);
	sb.append(" ");
	sb.append(digestid);
	if (digest != null) {
		sb.append(" ");
		sb.append(base16.toString(digest));
	}

	return sb.toString();
}	

/**
 * Returns the key's algorithm.
 */
public int
getAlgorithm() {
	return alg;
}

/**
 *  Returns the key's Digest ID.
 */
public int
getDigestID()
{
	return digestid;
}
  
/**
 * Returns the binary hash of the key.
 */
public byte []
getDigest() {
	return digest;
}

/**
 * Returns the key's footprint.
 */
public int
getFootprint() {
	return footprint;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	out.writeShort(footprint);
	out.writeByte(alg);
	out.writeByte(digestid);
	if (digest != null)
		out.writeArray(digest);
}

}

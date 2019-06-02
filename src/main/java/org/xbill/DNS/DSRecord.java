// Copyright (c) 2002-2004 Brian Wellington (bwelling@xbill.org)

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
 * @see <a href="https://tools.ietf.org/html/rfc4034">RFC 4034: Resource Records for the DNS Security Extensions</a>
 */
public class DSRecord extends Record {

public static class Digest {
	private Digest() {}

	/** SHA-1 */
	public static final int SHA1 = 1;

	/** SHA-256 */
	public static final int SHA256 = 2;

	/** GOST R 34.11-94 */
	public static final int GOST3411 = 3;
	
	/** SHA-384 */
	public static final int SHA384 = 4;
}

public static final int SHA1_DIGEST_ID = Digest.SHA1;
public static final int SHA256_DIGEST_ID = Digest.SHA256;
public static final int GOST3411_DIGEST_ID = Digest.GOST3411;
public static final int SHA384_DIGEST_ID = Digest.SHA384;

private static final long serialVersionUID = -9001819329700081493L;

private int footprint;
private int alg;
private int digestid;
private byte [] digest;

DSRecord() {}

@Override
Record
getObject() {
	return new DSRecord();
}

/**
 * Creates a DS Record from the given data
 * @param footprint The original KEY record's footprint (keyid).
 * @param alg The original key algorithm.
 * @param digestid The digest id code.
 * @param digest A hash of the original key.
 */
protected
DSRecord(Name name, int type, int dclass, long ttl, int footprint, int alg,
	 int digestid, byte [] digest)
{
	super(name, type, dclass, ttl);
	this.footprint = checkU16("footprint", footprint);
	this.alg = checkU8("alg", alg);
	this.digestid = checkU8("digestid", digestid);
	this.digest = digest;
}

/**
 * Creates a DS Record from the given data
 * @param footprint The original KEY record's footprint (keyid).
 * @param alg The original key algorithm.
 * @param digestid The digest id code.
 * @param digest A hash of the original key.
 */
public
DSRecord(Name name, int dclass, long ttl, int footprint, int alg,
	 int digestid, byte [] digest)
{
	this(name, Type.DS, dclass, ttl, footprint, alg, digestid, digest);
}

/**
 * Creates a DS Record from the given data
 * @param digestid The digest id code.
 * @param key The key to digest
 */
public
DSRecord(Name name, int dclass, long ttl, int digestid, DNSKEYRecord key)
{
	this(name, dclass, ttl, key.getFootprint(), key.getAlgorithm(),
	     digestid, DNSSEC.generateDSDigest(key, digestid));
}

@Override
void
rrFromWire(DNSInput in) throws IOException {
	footprint = in.readU16();
	alg = in.readU8();
	digestid = in.readU8();
	digest = in.readByteArray();
}

@Override
void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	footprint = st.getUInt16();
	alg = st.getUInt8();
	digestid = st.getUInt8();
	digest = st.getHex();
}

/**
 * Converts rdata to a String
 */
@Override
String
rrToString() {
	StringBuilder sb = new StringBuilder();
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

@Override
void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeU16(footprint);
	out.writeU8(alg);
	out.writeU8(digestid);
	if (digest != null)
		out.writeByteArray(digest);
}

}

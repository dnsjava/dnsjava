// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
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

private int footprint = -1;
private byte alg;
private byte digestid = SHA1_DIGEST_ID;
private byte [] digest;

private DSRecord() {}

private
DSRecord(Name name, short dclass, int ttl) {
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
DSRecord(Name name, short dclass, int ttl, int footprint, int alg,
	 int digestid, byte []  digest)
{
	this(name, dclass, ttl);
	this.footprint = footprint;
	this.alg = (byte) alg;
	this.digestid = (byte) digestid;
	this.digest = digest;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	DSRecord rec = new DSRecord(name, dclass, ttl);
	if (in == null)
		return rec;

	rec.footprint = in.readShort() & 0xFFFF;
	rec.alg = in.readByte();
	rec.digestid = in.readByte();

	if (length > 4) {
		rec.digest = new byte[length - 4];
		in.read(rec.digest);
	}
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	DSRecord rec = new DSRecord(name, dclass, ttl);
	rec.footprint = Integer.decode(nextString(st)).intValue();
	rec.alg = (byte) Integer.parseInt(nextString(st));
	rec.digestid = (byte) Integer.parseInt(nextString(st));

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
	sb.append(footprint & 0xFFFF);
	sb.append(" ");
	sb.append(alg & 0xFF);
	sb.append(" ");
	sb.append(digestid & 0xFF);
	if (digest != null) {
		sb.append(" ");
		sb.append(base16.toString(digest));
	}

	return sb.toString();
}	

/**
 * Returns the key's algorithm.
 */
public byte
getAlgorithm() {
	return alg;
}

/**
 *  Returns the key's Digest ID.
 */
public byte
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
public short
getFootprint() {
	return (short) footprint;
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

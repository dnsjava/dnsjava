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

private int footprint = -1;
private byte alg;
private byte digestid = SHA1_DIGEST_ID;
private byte [] digest;

private DSRecord() {}

/**
 * Creates a DS Record from the given data
 * @param footprint The original KEY record's footprint (keyid).
 * @param alg The original key algorithm.
 * @param digestid The digest id code.
 * @param digest A hash of the original key.  
 */
public
DSRecord(Name _name, short _dclass, int _ttl, int _footprint,
	 int _alg, int _digestid, byte []  _digest)
{
	super(_name, Type.DS, _dclass, _ttl);
	footprint = _footprint;
	alg = (byte) _alg;
	digestid = (byte) _digestid;
	digest = _digest;
}

DSRecord(Name _name, short _dclass, int _ttl, int length,
	 DataByteInputStream in)
throws IOException
{
	super(_name, Type.DS, _dclass, _ttl);
	if (in == null)
		return;

	footprint = in.readShort() & 0xFFFF;
	alg = in.readByte();
	digestid = in.readByte();

	if (length > 4) {
		digest = new byte[length - 4];
		in.read(digest);
	}
}

DSRecord(Name _name, short _dclass, int _ttl,
	 MyStringTokenizer st, Name origin)
throws IOException
{
	super(_name, Type.DS, _dclass, _ttl);

	footprint = Integer.decode(st.nextToken()).intValue();
	alg = (byte) Integer.parseInt(st.nextToken());
	digestid = (byte) Integer.parseInt(st.nextToken());

	// note that the draft says that the digest is presented as hex,
	// not base64.
	digest = base16.fromString(st.remainingTokens());
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	out.writeShort(footprint);
	out.writeByte(alg);
	out.writeByte(digestid);
	if (digest != null)
		out.write(digest);
}

}

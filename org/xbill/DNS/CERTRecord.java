// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Certificate Record  - Stores a certificate associated with a name.  The
 * certificate might also be associated with a KEYRecord.
 * @see KEYRecord
 *
 * @author Brian Wellington
 */

public class CERTRecord extends Record {

/** PKIX (X.509v3) */
public static final int PKIX = 1;

/** Simple Public Key Infrastructure  */
public static final int SPKI = 2;

/** Pretty Good Privacy */
public static final int PGP = 3;

/** Certificate stored in a URL */
public static final int URL = 253;

/** Object ID (private) */
public static final int OID = 254;

private static CERTRecord member = new CERTRecord();

private short certType, keyTag;
private byte alg;
private byte [] cert;

private
CERTRecord() {}

private
CERTRecord(Name name, short dclass, int ttl) {
	super(name, Type.CERT, dclass, ttl);
}

static CERTRecord
getMember() {
	return member;
}

/**
 * Creates a CERT Record from the given data
 * @param certType The type of certificate (see constants)
 * @param keyTag The ID of the associated KEYRecord, if present
 * @param alg The algorithm of the associated KEYRecord, if present
 * @param cert Binary data representing the certificate
 */
public
CERTRecord(Name name, short dclass, int ttl, int certType, int keyTag,
	   int alg, byte []  cert)
{
	this(name, dclass, ttl);
	this.certType = (short) certType;
	this.keyTag = (short) keyTag;
	this.alg = (byte) alg;
	this.cert = cert;
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	CERTRecord rec = new CERTRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.certType = in.readShort();
	rec.keyTag = (short) in.readUnsignedShort();
	rec.alg = in.readByte();
	if (length > 5) {
		rec.cert = new byte[length - 5];
		in.read(rec.cert);
	}
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
 		Name origin)
throws TextParseException
{
	CERTRecord rec = new CERTRecord(name, dclass, ttl);
	rec.certType = (short) Integer.parseInt(nextString(st));
	rec.keyTag = (short) Integer.parseInt(nextString(st));
	rec.alg = (byte) Integer.parseInt(nextString(st));
	rec.cert = base64.fromString(remainingStrings(st));
	return rec;
}

/**
 * Converts rdata to a String
 */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (cert != null) {
		sb.append (certType);
		sb.append (" ");
		sb.append (keyTag & 0xFFFF);
		sb.append (" ");
		sb.append (alg);
		if (cert != null) {
			if (Options.check("multiline")) {
				sb.append(" (\n");
				sb.append(base64.formatString(cert, 64,
							      "\t", true));
			} else {
				sb.append(" ");
				sb.append(base64.toString(cert));
			}
		}
	}
	return sb.toString();
}

/**
 * Returns the type of certificate
 */
public short
getCertType() {
	return certType;
}

/**
 * Returns the ID of the associated KEYRecord, if present
 */
public short
getKeyTag() {
	return keyTag;
}

/**
 * Returns the algorithm of the associated KEYRecord, if present
 */
public byte
getAlgorithm() {
	return alg;
}

/**
 * Returns the binary representation of the certificate
 */
public byte []
getCert() {
	return cert;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (cert == null)
		return;

	out.writeShort(certType);
	out.writeShort(keyTag);
	out.writeByte(alg);
	out.writeArray(cert);
}

}

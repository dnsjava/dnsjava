// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
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

private int certType, keyTag;
private int alg;
private byte [] cert;

private
CERTRecord() {}

private
CERTRecord(Name name, int dclass, long ttl) {
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
CERTRecord(Name name, int dclass, long ttl, int certType, int keyTag,
	   int alg, byte []  cert)
{
	this(name, dclass, ttl);
	checkU16("certType", certType);
	checkU16("keyTag", keyTag);
	checkU8("alg", alg);
	this.certType = certType;
	this.keyTag = keyTag;
	this.alg = alg;
	this.cert = cert;
}

Record
rrFromWire(Name name, int type, int dclass, long ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	CERTRecord rec = new CERTRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	rec.certType = in.readShort();
	rec.keyTag = in.readUnsignedShort();
	rec.alg = in.readByte();
	if (length > 5) {
		rec.cert = new byte[length - 5];
		in.read(rec.cert);
	}
	return rec;
}

Record
rdataFromString(Name name, int dclass, long ttl, Tokenizer st, Name origin)
throws IOException
{
	CERTRecord rec = new CERTRecord(name, dclass, ttl);
	rec.certType = st.getUInt16();
	rec.keyTag = st.getUInt16();
	rec.alg = st.getUInt8();
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
		sb.append (keyTag);
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
public int
getCertType() {
	return certType;
}

/**
 * Returns the ID of the associated KEYRecord, if present
 */
public int
getKeyTag() {
	return keyTag;
}

/**
 * Returns the algorithm of the associated KEYRecord, if present
 */
public int
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

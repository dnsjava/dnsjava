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

private short certType, keyTag;
private byte alg;
private byte [] cert;

private
CERTRecord() {}

/**
 * Creates a CERT Record from the given data
 * @param certType The type of certificate (see constants)
 * @param keyTag The ID of the associated KEYRecord, if present
 * @param alg The algorithm of the associated KEYRecord, if present
 * @param cert Binary data representing the certificate
 */
public
CERTRecord(Name _name, short _dclass, int _ttl, int _certType,
	      int _keyTag, int _alg, byte []  _cert)
{
	super(_name, Type.CERT, _dclass, _ttl);
	certType = (short) _certType;
	keyTag = (short) _keyTag;
	alg = (byte) _alg;
	cert = _cert;
}

CERTRecord(Name _name, short _dclass, int _ttl, int length,
	   DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.CERT, _dclass, _ttl);
	if (in == null)
		return;
	certType = in.readShort();
	keyTag = in.readShort();
	alg = in.readByte();
	if (length > 5) {
		cert = new byte[length - 5];
		in.read(cert);
	}
}

CERTRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	   Name origin)
throws IOException
{
	super(_name, Type.CERT, _dclass, _ttl);
	certType = (short) Integer.parseInt(st.nextToken());
	keyTag = (short) Integer.parseInt(st.nextToken());
	alg = (byte) Integer.parseInt(st.nextToken());
	cert = base64.fromString(st.nextToken());
}

/**
 * Converts to a String
 */
public String
toString() {
	StringBuffer sb = toStringNoData();
	if (cert != null) {
		sb.append (certType);
		sb.append (" ");
		sb.append (keyTag);
		sb.append (" ");
		sb.append (alg);
		if (cert != null) {
			sb.append (" (\n");
			sb.append (base64.formatString(cert, 64, "\t", true));
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (cert == null)
		return;

	out.writeShort(certType);
	out.writeShort(keyTag);
	out.writeByte(alg);
	out.write(cert);
}

}

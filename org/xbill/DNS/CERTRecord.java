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

public static class CertificateType {
	/** Certificate type identifiers.  See RFC 2538 for more detail. */

	private CertificateType() {}

	/** PKIX (X.509v3) */
	public static final int PKIX = 1;

	/** Simple Public Key Infrastructure */
	public static final int SPKI = 2;

	/** Pretty Good Privacy */
	public static final int PGP = 3;

	/** Certificate format defined by URI */
	public static final int URI = 253;

	/** Certificate format defined by OID */
	public static final int OID = 254;

	private static Mnemonic types = new Mnemonic("Certificate type",
						     Mnemonic.CASE_UPPER);

	static {
		types.setMaximum(0xFFFF);
		types.setNumericAllowed(true);

		types.add(PKIX, "PKIX");
		types.add(SPKI, "SPKI");
		types.add(PGP, "PGP");
		types.add(URI, "URI");
		types.add(OID, "OID");
	}

	/**
	 * Converts a certificate type into its textual representation
	 */
	public static String
	string(int type) {
		return types.getText(type);
	}

	/**
	 * Converts a textual representation of an certificate type into its
	 * numeric code.  Integers in the range 0..65535 are also accepted.
	 * @param s The textual representation of the algorithm
	 * @return The algorithm code, or -1 on error.
	 */
	public static int
	value(String s) {
		return types.getValue(s);
	}
}

/** PKIX (X.509v3) */
public static final int PKIX = CertificateType.PKIX;

/** Simple Public Key Infrastructure  */
public static final int SPKI = CertificateType.SPKI;

/** Pretty Good Privacy */
public static final int PGP = CertificateType.PGP;

/** Certificate format defined by URI */
public static final int URI = CertificateType.URI;

/** Certificate format defined by IOD */
public static final int OID = CertificateType.OID;

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
	String certTypeString = st.getString();
	int certType = CertificateType.value(certTypeString);
	if (certType < 0)
		throw st.exception("Invalid certificate type: " +
				   certTypeString);
	rec.certType = certType;
	rec.keyTag = st.getUInt16();
	String algString = st.getString();
	int alg = DNSSEC.Algorithm.value(algString);
	if (alg < 0)
		throw st.exception("Invalid algorithm: " + algString);
	rec.alg = alg;
	rec.cert = st.getBase64();
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

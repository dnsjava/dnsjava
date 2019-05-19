// Copyright (c) 2002-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * DS - contains a Delegation Signer record, which acts as a
 * placeholder for KEY records in the parent zone.
 * @see DNSSEC
 *
 * @author David Blacka
 * @author Brian Wellington
 */

public class DSRecord extends DSRecordBase {

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

DSRecord() {}

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
public
DSRecord(Name name, int dclass, long ttl, int footprint, int alg,
		 int digestid, byte[] digest)  {
	super(name, Type.DS, dclass, ttl, footprint, alg, digestid, digest);
}

/**
 * Creates a DS Record from the given data
 * @param digestid The digest id code.
 * @param key The key to digest
 */
public
DSRecord(Name name, int dclass, long ttl, int digestid, DNSKEYRecord key) {
	this(name, dclass, ttl, key.getFootprint(), key.getAlgorithm(), digestid, DNSSEC.generateDSDigest(key, digestid));
}
}

// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The base class for SIG/RRSIG records, which have identical formats 
 *
 * @author Brian Wellington
 */

abstract class SIGBase extends Record {

protected int covered;
protected int alg, labels;
protected long origttl;
protected Date expire, timeSigned;
protected int footprint;
protected Name signer;
protected byte [] signature;

protected
SIGBase() {}

protected
SIGBase(Name name, int type, int dclass, long ttl) {
	super(name, type, dclass, ttl);
}

public
SIGBase(Name name, int type, int dclass, long ttl, int covered, int alg,
	long origttl, Date expire, Date timeSigned, int footprint, Name signer,
	byte [] signature)
{
	super(name, type, dclass, ttl);
	Type.check(covered);
	checkU8("alg", alg);
	checkU8("labels", labels);
	TTL.check(origttl);
	checkU16("footprint", footprint);
	this.covered = covered;
	this.alg = alg;
	this.labels = name.labels();
	this.origttl = origttl;
	this.expire = expire;
	this.timeSigned = timeSigned;
	this.footprint = footprint;
	if (!signer.isAbsolute())
		throw new RelativeNameException(signer);
	this.signer = signer;
	this.signature = signature;
}

protected static Record
rrFromWire(SIGBase rec, DNSInput in)
throws IOException
{
	if (in == null)
		return rec;
	rec.covered = in.readU16();
	rec.alg = in.readU8();
	rec.labels = in.readU8();
	rec.origttl = in.readU32();
	rec.expire = new Date(1000 * in.readU32());
	rec.timeSigned = new Date(1000 * in.readU32());
	rec.footprint = in.readU16();
	rec.signer = new Name(in);
	rec.signature = in.readByteArray();
	return rec;
}

protected static Record
rdataFromString(SIGBase rec, Tokenizer st, Name origin)
throws IOException
{
	String typeString = st.getString();
	int covered = Type.value(typeString);
	if (covered < 0)
		throw st.exception("Invalid type: " + typeString);
	rec.covered = covered;
	String algString = st.getString();
	int alg = DNSSEC.Algorithm.value(algString);
	if (alg < 0)
		throw st.exception("Invalid algorithm: " + algString);
	rec.alg = alg;
	rec.labels = st.getUInt8();
	rec.origttl = st.getTTL();
	rec.expire = FormattedTime.parse(st.getString());
	rec.timeSigned = FormattedTime.parse(st.getString());
	rec.footprint = st.getUInt16();
	rec.signer = st.getName(origin);
	rec.signature = st.getBase64();
	return rec;
}

/** Converts the RRSIG/SIG Record to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (signature != null) {
		sb.append (Type.string(covered));
		sb.append (" ");
		sb.append (alg);
		sb.append (" ");
		sb.append (labels);
		sb.append (" ");
		sb.append (origttl);
		sb.append (" ");
		if (Options.check("multiline"))
			sb.append ("(\n\t");
		sb.append (FormattedTime.format(expire));
		sb.append (" ");
		sb.append (FormattedTime.format(timeSigned));
		sb.append (" ");
		sb.append (footprint);
		sb.append (" ");
		sb.append (signer);
		if (Options.check("multiline")) {
			sb.append("\n");
			sb.append(base64.formatString(signature, 64, "\t",
						      true));
		} else {
			sb.append (" ");
			sb.append(base64.toString(signature));
		}
	}
	return sb.toString();
}

/** Returns the RRset type covered by this signature */
public int
getTypeCovered() {
	return covered;
}

/**
 * Returns the cryptographic algorithm of the key that generated the signature
 */
public int
getAlgorithm() {
	return alg;
}

/**
 * Returns the number of labels in the signed domain name.  This may be
 * different than the record's domain name if the record is a wildcard
 * record.
 */
public int
getLabels() {
	return labels;
}

/** Returns the original TTL of the RRset */
public long
getOrigTTL() {
	return origttl;
}

/** Returns the time at which the signature expires */
public Date
getExpire() {
	return expire;
}

/** Returns the time at which this signature was generated */
public Date
getTimeSigned() {
	return timeSigned;
}

/** Returns The footprint/key id of the signing key.  */
public int
getFootprint() {
	return footprint;
}

/** Returns the owner of the signing key */
public Name
getSigner() {
	return signer;
}

/** Returns the binary data representing the signature */
public byte []
getSignature() {
	return signature;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (signature == null)
		return;

	out.writeUnsignedShort(covered);
	out.writeByte(alg);
	out.writeByte(labels);
	out.writeUnsignedInt(origttl);
	out.writeUnsignedInt(expire.getTime() / 1000);
	out.writeUnsignedInt(timeSigned.getTime() / 1000);
	out.writeShort(footprint);
	signer.toWire(out, null, canonical);
	out.writeArray(signature);
}

}

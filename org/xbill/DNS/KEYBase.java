// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * The base class for KEY/DNSKEY records, which have identical formats 
 *
 * @author Brian Wellington
 */

abstract class KEYBase extends Record {

protected int flags, proto, alg;
protected byte [] key;
protected int footprint = -1;

protected
KEYBase() {}

protected
KEYBase(Name name, int type, int dclass, long ttl) {
	super(name, type, dclass, ttl);
}

public
KEYBase(Name name, int type, int dclass, long ttl, int flags, int proto,
	int alg, byte [] key)
{
	super(name, type, dclass, ttl);
	checkU16("flags", flags);
	checkU8("proto", proto);
	checkU8("alg", alg);
	this.key = key;
}

protected static Record
rrFromWire(KEYBase rec, DNSInput in)
throws IOException
{
	if (in == null)
		return rec;
	rec.flags = in.readU16();
	rec.proto = in.readU8();
	rec.alg = in.readU8();
	if (in.remaining() > 0)
		rec.key = in.readByteArray();
	return rec;
}

private boolean
isNullKEY() {
	return (type == Type.KEY &&
		(flags & KEYRecord.FLAG_NOKEY) == KEYRecord.FLAG_NOKEY);
}

protected static Record
rdataFromString(KEYBase rec, Tokenizer st, Name origin)
throws IOException
{
	rec.flags = st.getUInt16();
	rec.proto = st.getUInt8();
	String algString = st.getString();
	int alg = DNSSEC.Algorithm.value(algString);
	if (alg < 0)
		throw st.exception("Invalid algorithm: " + algString);
	rec.alg = alg;
	/* If this is a null KEY, there's no key data */
	if (rec.isNullKEY())
		rec.key = null;
	else
		rec.key = st.getBase64();
	return rec;
}

/** Converts the DNSKEY/KEY Record to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (key != null || isNullKEY()) {
		sb.append(flags);
		sb.append(" ");
		sb.append(proto);
		sb.append(" ");
		sb.append(alg);
		if (key != null) {
			if (Options.check("multiline")) {
				sb.append(" (\n");
				sb.append(base64.formatString(key, 64, "\t",
							      true));
				sb.append(" ; key_tag = ");
				sb.append(getFootprint());
			} else {
				sb.append(" ");
				sb.append(base64.toString(key));
			}
		}
	}
	return sb.toString();
}

/**
 * Returns the flags describing the key's properties
 */
public int
getFlags() {
	return flags;
}

/**
 * Returns the protocol that the key was created for
 */
public int
getProtocol() {
	return proto;
}

/**
 * Returns the key's algorithm
 */
public int
getAlgorithm() {
	return alg;
}

/**
 * Returns the binary data representing the key
 */
public byte []
getKey() {
	return key;
}

/**
 * Returns the key's footprint (after computing it)
 */
public int
getFootprint() {
	if (footprint >= 0)
		return footprint;

	int foot = 0;

	DataByteOutputStream out = new DataByteOutputStream();
	rrToWire(out, null, false);
	byte [] rdata = out.toByteArray();

	if (alg == DNSSEC.Algorithm.RSAMD5) {
		int d1 = rdata[rdata.length - 3] & 0xFF;
		int d2 = rdata[rdata.length - 2] & 0xFF;
		foot = (d1 << 8) + d2;
	}
	else {
		int i; 
		for (i = 0; i < rdata.length - 1; i += 2) {
			int d1 = rdata[i] & 0xFF;
			int d2 = rdata[i + 1] & 0xFF;
			foot += ((d1 << 8) + d2);
		}
		if (i < rdata.length) {
			int d1 = rdata[i] & 0xFF;
			foot += (d1 << 8);
		}
		foot += ((foot >> 16) & 0xFFFF);
	}
	footprint = (foot & 0xFFFF);
	return footprint;
}

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (key == null && !isNullKEY())
		return;

	out.writeShort(flags);
	out.writeByte(proto);
	out.writeByte(alg);
	if (key != null)
		out.writeArray(key);
}

}

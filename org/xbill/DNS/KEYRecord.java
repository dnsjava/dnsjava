// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Key - contains a cryptographic public key.  The data can be converted
 * to objects implementing java.security.interfaces.PublicKey
 * @see DNSSEC
 *
 * @author Brian Wellington
 */

public class KEYRecord extends Record {

private short flags;
private byte proto, alg;
private byte [] key;
private int footprint = -1;

/* flags */
/** This key cannot be used for confidentiality (encryption) */
public static final int FLAG_NOCONF = 0x8000;

/** This key cannot be used for authentication */
public static final int FLAG_NOAUTH = 0x4000;

/** This key cannot be used for authentication or confidentiality */
public static final int FLAG_NOKEY = 0xC000;

/** A zone key */
public static final int OWNER_ZONE = 0x0100;

/** A host/end entity key */
public static final int OWNER_HOST = 0x0200;

/** A user key */
public static final int OWNER_USER = 0x0000;

/* protocols */
/** Key was created for use with transaction level security */
public static final int PROTOCOL_TLS = 1;

/** Key was created for use with email */
public static final int PROTOCOL_EMAIL = 2;

/** Key was created for use with DNSSEC */
public static final int PROTOCOL_DNSSEC = 3;

/** Key was created for use with IPSEC */
public static final int PROTOCOL_IPSEC = 4;

/** Key was created for use with any protocol */
public static final int PROTOCOL_ANY = 255;

private
KEYRecord() {}

/**
 * Creates a KEY Record from the given data
 * @param flags Flags describing the key's properties
 * @param proto The protocol that the key was created for
 * @param alg The key's algorithm
 * @param key Binary data representing the key
 */
public
KEYRecord(Name _name, short _dclass, int _ttl, int _flags, int _proto,
	  int _alg, byte []  _key)
{
	super(_name, Type.KEY, _dclass, _ttl);
	flags = (short) _flags;
	proto = (byte) _proto;
	alg = (byte) _alg;
	key = _key;
}

KEYRecord(Name _name, short _dclass, int _ttl,
	     int length, DataByteInputStream in, Compression c)
throws IOException
{
	super(_name, Type.KEY, _dclass, _ttl);
	if (in == null)
		return;
	flags = in.readShort();
	proto = in.readByte();
	alg = in.readByte();
	if (length > 4) {
		key = new byte[length - 4];
		in.read(key);
	}
}

KEYRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	  Name origin)
throws IOException
{
	super(_name, Type.KEY, _dclass, _ttl);
	flags = (short) Integer.decode(st.nextToken()).intValue();
	proto = (byte) Integer.parseInt(st.nextToken());
	alg = (byte) Integer.parseInt(st.nextToken());
	/* If this is a null key, there's no key data */
	if (!((flags & (FLAG_NOKEY)) == (FLAG_NOKEY)))
		key = base64.fromString(st.remainingTokens());
	else
		key = null;
}

/**
 * Converts rdata to a String
 */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (key != null || (flags & (FLAG_NOKEY)) == (FLAG_NOKEY) ) {
		if (!Options.check("nohex")) {
			sb.append("0x");
			sb.append(Integer.toHexString(flags & 0xFFFF));
		}
		else
			sb.append(flags & 0xFFFF);
		sb.append(" ");
		sb.append(proto & 0xFF);
		sb.append(" ");
		sb.append(alg & 0xFF);
		if (key != null) {
			sb.append(" (\n");
			sb.append(base64.formatString(key, 64, "\t", true));
			sb.append(" ; key_tag = ");
			sb.append(getFootprint() & 0xFFFF);
		}
	}
	return sb.toString();
}

/**
 * Returns the flags describing the key's properties
 */
public short
getFlags() {
	return flags;
}

/**
 * Returns the protocol that the key was created for
 */
public byte
getProtocol() {
	return proto;
}

/**
 * Returns the key's algorithm
 */
public byte
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
public short
getFootprint() {
	if (footprint >= 0)
		return (short)footprint;
	
	int foot = 0;

	DataByteOutputStream out = new DataByteOutputStream();
	try {
		rrToWire(out, null);
	}
	catch (IOException e) {}
	byte [] rdata = out.toByteArray();

	if (alg == DNSSEC.RSA) {
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
		foot += ((foot >> 16) & 0xffff);
	}
	footprint = (foot & 0xffff);
	return (short) footprint;
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (key == null && (flags & (FLAG_NOKEY)) != (FLAG_NOKEY) )
		return;

	out.writeShort(flags);
	out.writeByte(proto);
	out.writeByte(alg);
	if (key != null)
		out.write(key);
}

}

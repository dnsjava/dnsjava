// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import java.text.*;
import org.xbill.DNS.utils.*;

/**
 * Transaction Key - used to compute and/or securely transport a shared
 * secret to be used with TSIG.
 * @see TSIG
 *
 * @author Brian Wellington
 */

public class TKEYRecord extends Record {

private Name alg;
private Date timeInception;
private Date timeExpire;
private short mode, error;
private byte [] key;
private byte [] other;

/** The key is assigned by the server (unimplemented) */
public static final short SERVERASSIGNED	= 1;

/** The key is computed using a Diffie-Hellman key exchange */
public static final short DIFFIEHELLMAN		= 2;

/** The key is computed using GSS_API (unimplemented) */
public static final short GSSAPI		= 3;

/** The key is assigned by the resolver (unimplemented) */
public static final short RESOLVERASSIGNED	= 4;

/** The key should be deleted */
public static final short DELETE		= 5;

/**
 * Creates a TKEY Record from the given data.
 * @param alg The shared key's algorithm
 * @param timeInception The beginning of the validity period of the shared
 * secret or keying material
 * @param timeExpire The end of the validity period of the shared
 * secret or keying material
 * @param mode The mode of key agreement
 * @param error The extended error field.  Should be 0 in queries
 * @param key The shared secret
 * @param other The other data field.  Currently unused
 * responses.
 */
public
TKEYRecord(Name _name, short _dclass, int _ttl, Name _alg,
	   Date _timeInception, Date _timeExpire, short _mode, short _error,
	   byte [] _key, byte _other[]) throws IOException
{
	super(_name, Type.TKEY, _dclass, _ttl);
	alg = _alg;
	timeInception = _timeInception;
	timeExpire = _timeExpire;
	mode = _mode;
	error = _error;
	key = _key;
	other = _other;
}

TKEYRecord(Name _name, short _dclass, int _ttl, int length,
	   DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.TKEY, _dclass, _ttl);
	if (in == null)
		return;
	alg = new Name(in, c);
	timeInception = new Date(1000 * (long)in.readInt());
	timeExpire = new Date(1000 * (long)in.readInt());
	mode = in.readShort();
	error = in.readShort();

	int keylen = in.readUnsignedShort();
	if (keylen > 0) {
		key = new byte[keylen];
		in.read(key);
	}
	else
		key = null;

	int otherlen = in.readUnsignedShort();
	if (otherlen > 0) {
		other = new byte[otherlen];
		in.read(other);
	}
	else
		other = null;
}

protected String
modeString() {
	switch (mode) {
		case SERVERASSIGNED:	return "SERVERASSIGNED";
		case DIFFIEHELLMAN:	return "DIFFIEHELLMAN";
		case GSSAPI:		return "GSSAPRESOLVERASSIGNED";
		case RESOLVERASSIGNED:	return "RESOLVERASSIGNED";
		case DELETE:		return "DELETE";
		default:		return new Short(mode).toString();
	}
}

/** Converts rdata to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (alg == null)
		return sb.toString();

	sb.append(alg);
	sb.append(" (\n\t");

	sb.append(SIGRecord.formatDate(timeInception));
	sb.append (" ");
	sb.append(SIGRecord.formatDate(timeExpire));
	sb.append (" ");
	sb.append (modeString());
	sb.append (" ");
	sb.append (Rcode.TSIGstring(error));
	sb.append ("\n");
	if (key != null)
		sb.append (base64.formatString(key, 64, "\t", false));
	if (other != null)
		sb.append (base64.formatString(other, 64, "\t", false));
	sb.append(" )");
	return sb.toString();
}

/** Returns the shared key's algorithm */
public Name
getAlgorithm() {
	return alg;
}

/**
 * Returns the beginning of the validity period of the shared secret or
 * keying material
 */
public Date
getTimeInception() {
	return timeInception;
}

/**
 * Returns the end of the validity period of the shared secret or
 * keying material
 */
public Date
getTimeExpire() {
	return timeExpire;
}

/** Returns the key agreement mode */
public short
getMode() {
	return mode;
}

/** Returns the extended error */
public short
getError() {
	return error;
}

/** Returns the shared secret or keying material */
public byte []
getKey() {
	return key;
}

/** Returns the other data */
public byte []
getOther() {
	return other;
}

void
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
	if (alg == null)
		return;

	alg.toWire(out, null);

	out.writeInt((int)(timeInception.getTime() / 1000));
	out.writeInt((int)(timeExpire.getTime() / 1000));

	out.writeShort(mode);
	out.writeShort(error);

	if (key != null) {
		out.writeShort((short)key.length);
		out.write(key);
	}
	else
		out.writeShort(0);

	if (other != null) {
		out.writeShort((short)other.length);
		out.write(other);
	}
	else
		out.writeShort(0);
}

void
rrToWireCanonical(DataByteOutputStream out) throws IOException {
	throw new IOException("A TKEY should never be converted to canonical");
}

}

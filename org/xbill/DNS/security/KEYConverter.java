// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.security;

import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import org.xbill.DNS.*;
import org.xbill.DNS.utils.*;

/**
 * Routines to convert between a DNS KEY record and a Java PublicKey.
 *
 * @author Brian Wellington
 */

public class KEYConverter {

static int
BigIntegerLength(BigInteger i) {
	byte [] b = i.toByteArray();
	return (b[0] == 0 ? b.length - 1 : b.length);
}

static RSAPublicKey
parseRSA(DataByteInputStream in) throws IOException {
	int exponentLength = in.readUnsignedByte();
	if (exponentLength == 0)
		exponentLength = in.readUnsignedShort();
	BigInteger exponent = in.readBigInteger(exponentLength);

	int modulusLength = in.available();
	BigInteger modulus = in.readBigInteger(modulusLength);

	RSAPublicKey rsa = new RSAPubKey(modulus, exponent);
	return rsa;
}

static DHPublicKey
parseDH(DataByteInputStream in) throws IOException {
	int pLength = in.readUnsignedShort();
	if (pLength < 16)
		return null;
	BigInteger p = in.readBigInteger(pLength);

	int gLength = in.readUnsignedShort();
	BigInteger g = in.readBigInteger(gLength);

	int yLength = in.readUnsignedShort();
	BigInteger y = in.readBigInteger(yLength);

	return new DHPubKey(p, g, y);
}

static DSAPublicKey
parseDSA(DataByteInputStream in) throws IOException {
	byte t = in.readByte();

	BigInteger q = in.readBigInteger(20);
	BigInteger p = in.readBigInteger(64 + t*8);
	BigInteger g = in.readBigInteger(64 + t*8);
	BigInteger y = in.readBigInteger(64 + t*8);

	DSAPublicKey dsa = new DSAPubKey(p, q, g, y);
	return dsa;
}

/** Converts a KEY record into a PublicKey */
public static PublicKey
parseRecord(KEYRecord r) {
	byte alg = r.getAlgorithm();
	byte [] data = r.getKey();
	DataByteInputStream dbs = new DataByteInputStream(data); 
	try {
		switch (alg) {
			case DNSSEC.RSA:
				return parseRSA(dbs);
			case DNSSEC.DH:
				return parseDH(dbs);
			case DNSSEC.DSA:
				return parseDSA(dbs);
			default:
				return null;
		}
	}
	catch (IOException e) {
		if (Options.check("verboseexceptions"))
			System.err.println(e);
		return null;
	}
}

static byte []
buildRSA(RSAPublicKey key) {
	DataByteOutputStream out = new DataByteOutputStream();
	BigInteger exponent = key.getPublicExponent();
	BigInteger modulus = key.getModulus();
	int exponentLength = BigIntegerLength(exponent);

	if (exponentLength < 256)
		out.writeByte(exponentLength);
	else {
		out.writeByte(0);
		out.writeShort(exponentLength);
	}
	out.writeBigInteger(exponent);
	out.writeBigInteger(modulus);

	return out.toByteArray();
}

static byte []
buildDH(DHPublicKey key) {
	DataByteOutputStream out = new DataByteOutputStream();
	BigInteger p = key.getParams().getP();
	BigInteger g = key.getParams().getG();
	BigInteger y = key.getY();
	int pLength = BigIntegerLength(p);
	int gLength = BigIntegerLength(g);
	int yLength = BigIntegerLength(y);

	out.writeShort(pLength);
	out.writeBigInteger(p);
	out.writeShort(gLength);
	out.writeBigInteger(g);
	out.writeShort(yLength);
	out.writeBigInteger(y);

	return out.toByteArray();
}

static byte []
buildDSA(DSAPublicKey key) {
	DataByteOutputStream out = new DataByteOutputStream();
	BigInteger q = key.getParams().getQ();
	BigInteger p = key.getParams().getP();
	BigInteger g = key.getParams().getG();
	BigInteger y = key.getY();
	int t = (p.toByteArray().length - 64) / 8;

	out.writeByte(t);
	out.writeBigInteger(q);
	out.writeBigInteger(p);
	out.writeBigInteger(g);
	out.writeBigInteger(y);

	return out.toByteArray();
}

/** Builds a KEY record from a PublicKey */
public static KEYRecord
buildRecord(Name name, short dclass, int ttl, int flags, int proto,
	    PublicKey key)
{
	byte [] data;
	byte alg;

	if (key instanceof RSAPublicKey) {
		alg = DNSSEC.RSA;
		data = buildRSA((RSAPublicKey) key);
	}
	else if (key instanceof DHPublicKey) {
		alg = DNSSEC.DH;
		data = buildDH((DHPublicKey) key);
	}
	else if (key instanceof DSAPublicKey) {
		alg = DNSSEC.DSA;
		data = buildDSA((DSAPublicKey) key);
	}
	else
		return null;

	if (data == null)
		return null;

	return new KEYRecord(name, dclass, ttl, flags, proto, alg, data);
}

}

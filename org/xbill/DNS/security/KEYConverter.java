// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import javax.crypto.interfaces.*;
import org.xbill.DNS.*;
import org.xbill.DNS.utils.*;

/**
 * Routines to convert between a DNS KEY record and a Java PublicKey.
 *
 * @author Brian Wellington
 */

public class KEYConverter {

private static final BigInteger DHPRIME768 = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16);
private static final BigInteger DHPRIME1024 = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
private static final BigInteger TWO = new BigInteger("2", 16);

static int
BigIntegerLength(BigInteger i) {
	byte [] b = i.toByteArray();
	return (b[0] == 0 ? b.length - 1 : b.length);
}

static BigInteger
readBigInteger(DataInputStream in, int len) throws IOException {
	byte [] b = new byte[len];
	int n = in.read(b);
	if (n < len)
		throw new IOException("end of input");
	return new BigInteger(1, b);
}

static void
writeBigInteger(ByteArrayOutputStream out, BigInteger val) {
	byte [] b = val.toByteArray();
	if (b[0] == 0)
		out.write(b, 1, b.length - 1);
	else
		out.write(b, 0, b.length);
}

static void
writeShort(ByteArrayOutputStream out, int i) {
	out.write((i >> 8) & 0xFF);
	out.write(i & 0xFF);
}

static RSAPublicKey
parseRSA(DataInputStream in) throws IOException {
	int exponentLength = in.readUnsignedByte();
	if (exponentLength == 0)
		exponentLength = in.readUnsignedShort();
	BigInteger exponent = readBigInteger(in, exponentLength);

	int modulusLength = in.available();
	BigInteger modulus = readBigInteger(in, modulusLength);

	RSAPublicKey rsa = new RSAPubKey(modulus, exponent);
	return rsa;
}

static DHPublicKey
parseDH(DataInputStream in) throws IOException {
	int special = 0;
	int pLength = in.readUnsignedShort();
	if (pLength < 16 && pLength != 1 && pLength != 2)
		return null;
	BigInteger p;
	if (pLength == 1 || pLength == 2) {
		if (pLength == 1)
			special = in.readUnsignedByte();
		else
			special = in.readUnsignedShort();
		if (special != 1 && special != 2)
			return null;
		if (special == 1)
			p = DHPRIME768;
		else
			p = DHPRIME1024;
	}
	else
		p = readBigInteger(in, pLength);

	int gLength = in.readUnsignedShort();
	BigInteger g;
	if (gLength == 0) {
		if (special != 0)
			g = TWO;
		else
			return null;
	}
	else
		g = readBigInteger(in, gLength);

	int yLength = in.readUnsignedShort();
	BigInteger y = readBigInteger(in, yLength);

	return new DHPubKey(p, g, y);
}

static DSAPublicKey
parseDSA(DataInputStream in) throws IOException {
	byte t = in.readByte();

	BigInteger q = readBigInteger(in, 20);
	BigInteger p = readBigInteger(in, 64 + t*8);
	BigInteger g = readBigInteger(in, 64 + t*8);
	BigInteger y = readBigInteger(in, 64 + t*8);

	DSAPublicKey dsa = new DSAPubKey(p, q, g, y);
	return dsa;
}

/** Converts a KEY/DNSKEY record into a PublicKey */
static PublicKey
parseRecord(int alg, byte [] data) {
	ByteArrayInputStream bytes = new ByteArrayInputStream(data); 
	DataInputStream in = new DataInputStream(bytes);
	try {
		switch (alg) {
			case DNSSEC.RSAMD5:
			case DNSSEC.RSASHA1:
				return parseRSA(in);
			case DNSSEC.DH:
				return parseDH(in);
			case DNSSEC.DSA:
				return parseDSA(in);
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

/** Converts a DNSKEY record into a PublicKey */
public static PublicKey
parseRecord(DNSKEYRecord r) {
	int alg = r.getAlgorithm();
	byte [] data = r.getKey();
	return parseRecord(alg, data);
}

/** Converts a KEY record into a PublicKey */
public static PublicKey
parseRecord(KEYRecord r) {
	int alg = r.getAlgorithm();
	byte [] data = r.getKey();
	return parseRecord(alg, data);
}

static byte []
buildRSA(RSAPublicKey key) {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	BigInteger exponent = key.getPublicExponent();
	BigInteger modulus = key.getModulus();
	int exponentLength = BigIntegerLength(exponent);

	if (exponentLength < 256)
		out.write(exponentLength);
	else {
		out.write(0);
		writeShort(out, exponentLength);
	}
	writeBigInteger(out, exponent);
	writeBigInteger(out, modulus);

	return out.toByteArray();
}

static byte []
buildDH(DHPublicKey key) {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	BigInteger p = key.getParams().getP();
	BigInteger g = key.getParams().getG();
	BigInteger y = key.getY();

	int pLength, gLength, yLength;
	if (g.equals(TWO) && (p.equals(DHPRIME768) || p.equals(DHPRIME1024))) {
		pLength = 1;
		gLength = 0;
	}
	else {
		pLength = BigIntegerLength(p);
		gLength = BigIntegerLength(g);
	}
	yLength = BigIntegerLength(y);

	writeShort(out, pLength);
	if (pLength == 1) {
		if (p.bitLength() == 768)
			out.write(1);
		else
			out.write(2);
	}
	else
		writeBigInteger(out, p);
	writeShort(out, gLength);
	if (gLength > 0)
		writeBigInteger(out, g);
	writeShort(out, yLength);
	writeBigInteger(out, y);

	return out.toByteArray();
}

static byte []
buildDSA(DSAPublicKey key) {
	ByteArrayOutputStream out = new ByteArrayOutputStream();
	BigInteger q = key.getParams().getQ();
	BigInteger p = key.getParams().getP();
	BigInteger g = key.getParams().getG();
	BigInteger y = key.getY();
	int t = (p.toByteArray().length - 64) / 8;

	out.write(t);
	writeBigInteger(out, q);
	writeBigInteger(out, p);
	writeBigInteger(out, g);
	writeBigInteger(out, y);

	return out.toByteArray();
}

/** Builds a KEY record from a PublicKey */
public static KEYRecord
buildRecord(Name name, int dclass, long ttl, int flags, int proto,
	    PublicKey key)
{
	byte [] data;
	byte alg;

	if (key instanceof RSAPublicKey) {
		alg = DNSSEC.RSAMD5;
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

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.utils;

import java.io.*;

/**
 * A pure java implementation of the HMAC-MD5 secure hash algorithm
 */

public class hmacSigner {

private byte [] ipad, opad;
private ByteArrayOutputStream bytes;

private static final byte IPAD = 0x36;
private static final byte OPAD = 0x5c;
private static final byte PADLEN = 64;

private static void
printByteString(String s, byte [] b, int offset, int length) {
	System.out.print(length + " bytes (" + s + "): ");
	for (int i=offset; i<offset+length; i++)
		System.out.print(Integer.toHexString((int)b[i] & 0xFF) + " ");
	System.out.println();
}

/**
 * Creates a new HMAC instance
 * @param key The secret key
 */
public
hmacSigner(byte [] key) {
	int i;
	if (key.length > PADLEN)
		key = md5.compute(key);
	ipad = new byte[PADLEN];
	opad = new byte[PADLEN];
	for (i = 0; i < key.length; i++) {
		ipad[i] = (byte) (key[i] ^ IPAD);
		opad[i] = (byte) (key[i] ^ OPAD);
	}
	for (; i < PADLEN; i++) {
		ipad[i] = IPAD;
		opad[i] = OPAD;
	}
	bytes = new ByteArrayOutputStream();
	try {
		bytes.write(ipad);
	}
	catch (IOException e) {
	}
/*	printByteString("key", key, 0, key.length);*/
}

/**
 * Adds data to the current hash
 * @param b The data
 * @param start The index at which to start adding to the hash
 * @param len The number of bytes to hash
 */
public void
addData(byte [] b, int offset, int length) {
	if (length < offset || offset >= b.length || length >= b.length)
		return;
/*	printByteString("partial add", b, offset, length);*/
	bytes.write(b, offset, length);
}

/**
 * Adds data to the current hash
 * @param b The data
 */
public void
addData(byte [] b) {
/*	printByteString("add", b, 0, b.length);*/
	try {
		bytes.write(b);
	}
	catch (IOException e) {
	}
}

/**
 * Signs the data (computes the secure hash)
 * @return An array with the signature
 */
public byte []
sign() {
	byte [] output = md5.compute(bytes.toByteArray());
	bytes = new ByteArrayOutputStream();
	try {
		bytes.write(opad);
		bytes.write(output);
	}
	catch (IOException e) {
	}
	byte [] b = md5.compute(bytes.toByteArray());
/*	printByteString("sig", b, 0, b.length);*/
	return b;
}

/**
 * Verifies the data (computes the secure hash and compares it to the input)
 * @param signature The signature to compare against
 * @return true if the signature matched, false otherwise
 */
public boolean
verify(byte [] signature) {
/*	printByteString("ver", signature, 0, signature.length);*/
	return (byteArrayCompare(signature, sign()));
}

/**
 * Resets the HMAC object for further use
 */
public void
clear() {
	bytes = new ByteArrayOutputStream();
	try {
		bytes.write(ipad);
	}
	catch (IOException e) {
	}
}

private static boolean
byteArrayCompare(byte [] b1, byte [] b2) {
	if (b1.length != b2.length)
		return false;
	for (int i = 0; i < b1.length; i++)
		if (b1[i] != b2[i])
			return false;
	return true;
}

}

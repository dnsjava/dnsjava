// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.utils;

import java.util.Arrays;
import java.security.*;

/**
 * An implementation of the HMAC message authentication code.
 *
 * @author Brian Wellington
 */

public class HMAC {

MessageDigest digest;
private byte [] ipad, opad;

private static final byte IPAD = 0x36;
private static final byte OPAD = 0x5c;
private static final byte PADLEN = 64;

private void
init(byte [] key) {
	int i;

	if (key.length > PADLEN) {
		key = digest.digest(key);
		digest.reset();
	}
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
	digest.update(ipad);
}

/**
 * Creates a new HMAC instance
 * @param digest The message digest object.
 * @param key The secret key
 */
public
HMAC(MessageDigest digest, byte [] key) {
	digest.reset();
	this.digest = digest;
	init(key);
}

/**
 * Creates a new HMAC instance
 * @param digestName The name of the message digest function.
 * @param key The secret key.
 */
public
HMAC(String digestName, byte [] key) {
	try {
		digest = MessageDigest.getInstance(digestName);
	} catch (NoSuchAlgorithmException e) {
		throw new IllegalArgumentException("unknown digest algorithm "
						   + digestName);
	}
	init(key);
}

/**
 * Adds data to the current hash
 * @param b The data
 * @param offset The index at which to start adding to the hash
 * @param length The number of bytes to hash
 */
public void
update(byte [] b, int offset, int length) {
	digest.update(b, offset, length);
}

/**
 * Adds data to the current hash
 * @param b The data
 */
public void
update(byte [] b) {
	digest.update(b);
}

/**
 * Signs the data (computes the secure hash)
 * @return An array with the signature
 */
public byte []
sign() {
	byte [] output = digest.digest();
	digest.reset();
	digest.update(opad);
	return digest.digest(output);
}

/**
 * Verifies the data (computes the secure hash and compares it to the input)
 * @param signature The signature to compare against
 * @return true if the signature matched, false otherwise
 */
public boolean
verify(byte [] signature) {
	return Arrays.equals(signature, sign());
}

/**
 * Resets the HMAC object for further use
 */
public void
clear() {
	digest.reset();
	digest.update(ipad);
}

}

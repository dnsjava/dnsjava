// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.math.*;
import java.security.interfaces.*;

/**
 * A stub implementation of an RSA public key
 *
 * @author Brian Wellington
 */

class RSAPubKey implements RSAPublicKey {

private BigInteger Modulus, Exponent;

/** Create an RSA public key from its parts */
public
RSAPubKey(BigInteger modulus, BigInteger exponent) {
	Modulus = modulus;
	Exponent = exponent;
}

/** Obtain the modulus of an RSA public key */
public BigInteger
getModulus() {
	return Modulus;
}

/** Obtain the exponent of an RSA public key */
public BigInteger
getPublicExponent() {
	return Exponent;
}

/** Obtain the algorithm of an RSA public key */
public String
getAlgorithm() {
	return "RSA";
}

/** Obtain the format of an RSA public key (unimplemented) */
public String
getFormat() {
	return null;
}

/** Obtain the encoded representation of an RSA public key (unimplemented) */
public byte []
getEncoded() {
	return null;
}

}

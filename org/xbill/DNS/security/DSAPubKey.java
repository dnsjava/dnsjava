// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.math.*;
import java.security.interfaces.*;

/**
 * A stub implementation of a DSA (Digital Signature Algorithm) public key
 *
 * @author Brian Wellington
 */

class DSAPubKey implements DSAPublicKey {

static class SimpleDSAParams implements DSAParams {
	private BigInteger P, Q, G;

	public
	SimpleDSAParams(BigInteger p, BigInteger q, BigInteger g) {
		P = p;
		Q = q;
		G = g;
	}

	public BigInteger
	getP() {
		return P;
	}
		
	public BigInteger
	getQ() {
		return Q;
	}
		
	public BigInteger
	getG() {
		return G;
	}
}

private DSAParams params;
private BigInteger Y;

/** Create a DSA public key from its parts */
public
DSAPubKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
	params = (DSAParams) new SimpleDSAParams(p, q, g);
	Y = y;
}

/** Obtain the public value of a DSA public key */
public BigInteger
getY() {
	return Y;
}

/** Obtain the parameters of a DSA public key */
public DSAParams
getParams() {
	return params;
}

/** Obtain the algorithm of a DSA public key */
public String
getAlgorithm() {
	return "DSA";
}

/** Obtain the format of a DSA public key (unimplemented) */
public String
getFormat() {
	return null;
}

/** Obtain the encoded representation of a DSA public key (unimplemented) */
public byte []
getEncoded() {
	return null;
}

}

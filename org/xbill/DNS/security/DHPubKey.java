// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.math.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

/**
 * A stub implementation of a Diffie-Hellman public key
 *
 * @author Brian Wellington
 */

class DHPubKey implements DHPublicKey {

private DHParameterSpec params;
private BigInteger Y;

/** Create a Diffie-Hellman public key from its parts */
public
DHPubKey(BigInteger p, BigInteger g, BigInteger y) {
	params = new DHParameterSpec(p, g);
	Y = y;
}

/** Obtain the public value of a Diffie-Hellman public key */
public BigInteger
getY() {
	return Y;
}

/** Obtain the parameters of a Diffie-Hellman public key */
public DHParameterSpec
getParams() {
	return params;
}

/** Obtain the algorithm of a Diffie-Hellman public key */
public String
getAlgorithm() {
	return "DH";
}

/** Obtain the format of a Diffie-Hellman public key (unimplemented) */
public String
getFormat() {
	return null;
}

/**
 * Obtain the encoded representation of a Diffie-Hellman public key
 * (unimplemented)
 */
public byte []
getEncoded() {
	return null;
}

public String
toString() {
	StringBuffer sb = new StringBuffer();
	sb.append("P = ");
	sb.append(params.getP());
	sb.append("\nG = ");
	sb.append(params.getG());
	sb.append("\nY = ");
	sb.append(Y);
	return sb.toString();
}

}

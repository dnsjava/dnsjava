// Copyright (c) 2001-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAKey;
import java.util.Date;
import org.xbill.DNS.*;

/**
 * Creates SIG(0) transaction signatures.
 *
 * @author Pasi Eronen
 * @author Brian Wellington
 */

public class SIG0Signer {

/**
 * The default validity period for outgoing SIG(0) signed messages.
 * Can be overriden by the sig0validity option.
 */
private static final short VALIDITY = 300;
    
private int algorithm;
private PrivateKey privateKey;
private Name name;
private int footprint;

/** 
 * Creates a new SIG(0) signer object.
 * @param algorithm usually DNSSEC.RSAMD5, DNSSEC.DSA, or DNSSEC.RSASHA1
 * @param privateKey signing key (must match algorithm)
 * @param name the name of the key
 * @param keyFootprint the key tag
 */
public
SIG0Signer(int algorithm, PrivateKey privateKey, Name name, int keyFootprint) {
	this.algorithm = (byte) algorithm;
	this.privateKey = privateKey;
	this.name = name;
	this.footprint = keyFootprint;
}

/**
 * Creates a new SIG(0) signer object. This is the same as the
 * other constructor, except that the key tag is calculated automatically
 * from the given public key.
 */
public
SIG0Signer(int algorithm, PrivateKey privateKey, Name name,
	   PublicKey publicKey)
{
    this.algorithm = (byte) algorithm;
    this.privateKey = privateKey;
    this.name = name;
    KEYRecord keyRecord = KEYConverter.buildRecord(name, DClass.IN, 0,
						   KEYRecord.OWNER_USER,
						   KEYRecord.PROTOCOL_ANY,
						   publicKey);
    this.footprint = keyRecord.getFootprint();
}

/**
 * Appends a SIG(0) signature to the message.
 * @param m the message
 * @param old if this message is a response, the original message
 */
public void apply(Message m, byte [] old)
throws IOException, SignatureException, InvalidKeyException,
       NoSuchAlgorithmException
{
	
	int validity = Options.intValue("sig0validity");
	if (validity < 0)
		validity = VALIDITY;

	long now = System.currentTimeMillis();
	Date timeSigned = new Date(now);
	Date timeExpires = new Date(now + validity * 1000);
	
	String algorithmName;
	if (algorithm == DNSSEC.DSA) {
		algorithmName = "SHA1withDSA";
	} else if (algorithm == DNSSEC.RSAMD5) {
		algorithmName = "MD5withRSA";
	} else if (algorithm == DNSSEC.RSASHA1) {
		algorithmName = "SHA1withRSA";
	} else {
		throw new NoSuchAlgorithmException("Unknown algorithm");
	}

	SIGRecord tmpsig = new SIGRecord(Name.root, DClass.ANY, 0, 0,
					 algorithm, 0, timeExpires, timeSigned,
					 footprint, name, null);
	
	byte [] outBytes = DNSSEC.digestMessage(tmpsig, m, old);
	
	Signature signer = Signature.getInstance(algorithmName);
	signer.initSign(privateKey);
	signer.update(outBytes);
	byte [] signature = signer.sign();

	/*
	 * RSA signatures are already in correct format, but Java DSA
	 * routines use ASN.1; convert this to SIG format.
	 */
	if (algorithm == DNSSEC.DSA) {
		DSAKey dsakey = (DSAKey) privateKey;
		signature = DSASignature.create(dsakey.getParams(), signature);
	}
	
	SIGRecord sig = new SIGRecord(Name.root, DClass.ANY, 0, 0, algorithm,
				      0, timeExpires, timeSigned, footprint,
				      name, signature);
	m.addRecord(sig, Section.ADDITIONAL);
}

}

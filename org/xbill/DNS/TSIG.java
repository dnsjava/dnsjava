// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.util.*;
import org.xbill.DNS.utils.*;

/**
 * Transaction signature handling.  This class generates and verifies
 * TSIG records on messages, which provide transaction security.
 * @see TSIGRecord
 *
 * @author Brian Wellington
 */

public class TSIG {

/**
 * The domain name representing the HMAC-MD5 algorithm (the only supported
 * algorithm)
 */
public static final Name HMAC		= Name.fromConstantString
						("HMAC-MD5.SIG-ALG.REG.INT.");

/** The default fudge value for outgoing packets.  Can be overriden by the
 * tsigfudge option.
 */
public static final short FUDGE		= 300;

private Name name, alg;
private byte [] key;

static {
	if (Options.check("verbosehmac"))
		hmacSigner.verbose = true;
}

/**
 * Creates a new TSIG object, which can be used to sign or verify a message.
 * @param name The name of the shared key
 * @param key The shared key's data
 */
public
TSIG(Name name, byte [] key) {
	this.name = name;
	this.alg = HMAC;
	this.key = key;
}

/**
 * Creates a new TSIG object, which can be used to sign or verify a message.
 * @param name The name of the shared key
 * @param key The shared key's data, represented as either a base64 encoded
 * string or (if the first character is ':') a hex encoded string
 * @throws IllegalArgumentException The key name is an invalid name
 * @throws IllegalArgumentException The key data is improperly encoded
 */
public
TSIG(String name, String key) {
	byte [] keyArray;
	Name keyname;
	if (key.length() > 1 && key.charAt(0) == ':')
		keyArray = base16.fromString(key.substring(1));
	else
		keyArray = base64.fromString(key);
	if (keyArray == null)
		throw new IllegalArgumentException("Invalid TSIG key string");
	try {
		keyname = Name.fromString(name, Name.root);
	}
	catch (TextParseException e) {
		throw new IllegalArgumentException("Invalid TSIG key name");
	}
	this.name = keyname;
	this.alg = HMAC;
	this.key = keyArray;
}

/**
 * Generates a TSIG record with a specific error for a message that has
 * been rendered.
 * @param m The message
 * @param b The rendered message
 * @param error The error
 * @param old If this message is a response, the TSIG from the request
 * @return The TSIG record to be added to the message
 */
public TSIGRecord
generate(Message m, byte [] b, byte error, TSIGRecord old) {
	Date timeSigned;
	if (error != Rcode.BADTIME)
		timeSigned = new Date();
	else
		timeSigned = old.getTimeSigned();
	int fudge;
	hmacSigner h = null;
	if (error == Rcode.NOERROR || error == Rcode.BADTIME)
		h = new hmacSigner(key);

	fudge = Options.intValue("tsigfudge");
	if (fudge < 0 || fudge > 0x7FFF)
		fudge = FUDGE;

	if (old != null) {
		DataByteOutputStream dbs = new DataByteOutputStream();
		dbs.writeShort((short)old.getSignature().length);
		if (h != null) {
			h.addData(dbs.toByteArray());
			h.addData(old.getSignature());
		}
	}

	/* Digest the message */
	if (h != null)
		h.addData(b);

	DataByteOutputStream out = new DataByteOutputStream();
	name.toWireCanonical(out);
	out.writeShort(DClass.ANY);	/* class */
	out.writeInt(0);		/* ttl */
	alg.toWireCanonical(out);
	long time = timeSigned.getTime() / 1000;
	short timeHigh = (short) (time >> 32);
	int timeLow = (int) (time);
	out.writeShort(timeHigh);
	out.writeInt(timeLow);
	out.writeShort((short)fudge);

	out.writeShort(error);
	out.writeShort(0); /* No other data */

	if (h != null)
		h.addData(out.toByteArray());

	byte [] signature;
	if (h != null)
		signature = h.sign();
	else
		signature = new byte[0];

	byte [] other = null;
	if (error == Rcode.BADTIME) {
		out = new DataByteOutputStream();
		time = new Date().getTime() / 1000;
		timeHigh = (short) (time >> 32);
		timeLow = (int) (time);
		out.writeShort(timeHigh);
		out.writeInt(timeLow);
		other = out.toByteArray();
	}

	return (new TSIGRecord(name, DClass.ANY, 0, alg, timeSigned,
			       (short)fudge, signature,
			       m.getHeader().getID(), error, other));
}

/**
 * Generates a TSIG record with a specific error for a message and adds it
 * to the message.
 * @param m The message
 * @param error The error
 * @param old If this message is a response, the TSIG from the request
 */
public void
apply(Message m, byte error, TSIGRecord old) {
	Record r = generate(m, m.toWire(), error, old);
	m.addRecord(r, Section.ADDITIONAL);
}

/**
 * Generates a TSIG record for a message and adds it to the message
 * @param m The message
 * @param old If this message is a response, the TSIG from the request
 */
public void
apply(Message m, TSIGRecord old) {
	apply(m, Rcode.NOERROR, old);
}

/**
 * Generates a TSIG record for a message and adds it to the message
 * @param m The message
 * @param old If this message is a response, the TSIG from the request
 */
public void
applyStream(Message m, TSIGRecord old, boolean first) {
	if (first) {
		apply(m, old);
		return;
	}
	Date timeSigned = new Date();
	int fudge;
	hmacSigner h = new hmacSigner(key);

	fudge = Options.intValue("tsigfudge");
	if (fudge < 0 || fudge > 0x7FFF)
		fudge = FUDGE;

	DataByteOutputStream dbs = new DataByteOutputStream();
	dbs.writeShort((short)old.getSignature().length);
	h.addData(dbs.toByteArray());
	h.addData(old.getSignature());

	/* Digest the message */
	h.addData(m.toWire());

	DataByteOutputStream out = new DataByteOutputStream();
	long time = timeSigned.getTime() / 1000;
	short timeHigh = (short) (time >> 32);
	int timeLow = (int) (time);
	out.writeShort(timeHigh);
	out.writeInt(timeLow);
	out.writeShort((short)fudge);

	h.addData(out.toByteArray());

	byte [] signature = h.sign();
	byte [] other = null;

	Record r = new TSIGRecord(name, DClass.ANY, 0, alg, timeSigned,
				  (short)fudge, signature,
				  m.getHeader().getID(), Rcode.NOERROR, other);
	m.addRecord(r, Section.ADDITIONAL);
}

/**
 * Verifies a TSIG record on an incoming message.  Since this is only called
 * in the context where a TSIG is expected to be present, it is an error
 * if one is not present.
 * @param m The message
 * @param b An array containing the message in unparsed form.  This is
 * necessary since TSIG signs the message in wire format, and we can't
 * recreate the exact wire format (with the same name compression).
 * @param length The length of the message in the array.
 * @param old If this message is a response, the TSIG from the request
 * @return The result of the verification (as an Rcode)
 * @see Rcode
 */
public byte
verify(Message m, byte [] b, int length, TSIGRecord old) {
	TSIGRecord tsig = m.getTSIG();
	hmacSigner h = new hmacSigner(key);
	if (tsig == null)
		return Rcode.FORMERR;

	if (!tsig.getName().equals(name) || !tsig.getAlgorithm().equals(alg)) {
		if (Options.check("verbose"))
			System.err.println("BADKEY failure");
		return Rcode.BADKEY;
	}
	long now = System.currentTimeMillis();
	long then = tsig.getTimeSigned().getTime();
	long fudge = tsig.getFudge();
	if (Math.abs(now - then) > fudge * 1000) {
		if (Options.check("verbose"))
			System.err.println("BADTIME failure");
		return Rcode.BADTIME;
	}

	try {
		if (old != null && tsig.getError() != Rcode.BADKEY &&
		    tsig.getError() != Rcode.BADSIG)
		{
			DataByteOutputStream dbs = new DataByteOutputStream();
			dbs.writeShort((short)old.getSignature().length);
			h.addData(dbs.toByteArray());
			h.addData(old.getSignature());
		}
		m.getHeader().decCount(Section.ADDITIONAL);
		byte [] header = m.getHeader().toWire();
		m.getHeader().incCount(Section.ADDITIONAL);
		h.addData(header);

		int len = m.tsigstart - header.length;	
		h.addData(b, header.length, len);

		DataByteOutputStream out = new DataByteOutputStream();
		tsig.getName().toWireCanonical(out);
		out.writeShort(tsig.dclass);
		out.writeInt(tsig.ttl);
		tsig.getAlgorithm().toWireCanonical(out);
		long time = tsig.getTimeSigned().getTime() / 1000;
		short timeHigh = (short) (time >> 32);
		int timeLow = (int) (time);
		out.writeShort(timeHigh);
		out.writeInt(timeLow);
		out.writeShort(tsig.getFudge());
		out.writeShort(tsig.getError());
		if (tsig.getOther() != null) {
			out.writeShort(tsig.getOther().length);
			out.write(tsig.getOther());
		}
		else
			out.writeShort(0);

		h.addData(out.toByteArray());
	}
	catch (IOException e) {
		return Rcode.SERVFAIL;
	}

	if (h.verify(tsig.getSignature()))
		return Rcode.NOERROR;
	else {
		if (Options.check("verbose"))
			System.err.println("BADSIG failure");
		return Rcode.BADSIG;
	}
}

/**
 * Verifies a TSIG record on an incoming message.  Since this is only called
 * in the context where a TSIG is expected to be present, it is an error
 * if one is not present.
 * @param m The message
 * @param b The message in unparsed form.  This is necessary since TSIG
 * signs the message in wire format, and we can't recreate the exact wire
 * format (with the same name compression).
 * @param old If this message is a response, the TSIG from the request
 * @return The result of the verification (as an Rcode)
 * @see Rcode
 */
public byte
verify(Message m, byte [] b, TSIGRecord old) {
	return verify(m, b, b.length, old);
}

/**
 * Returns the maximum length of a TSIG record generated by this key.
 * @see TSIGRecord
 */
public int
recordLength() {
	return (name.length() + 10 +
		HMAC.length() +
		8 +	// time signed, fudge
		18 +	// 2 byte MAC length, 16 byte MAC
		4 +	// original id, error
		8);	// 2 byte error length, 6 byte max error field.
}

public static class StreamVerifier {
	private TSIG key;
	private hmacSigner verifier;
	private int nresponses;
	private int lastsigned;
	private TSIGRecord lastTSIG;

	/** Creates an object to verify a multiple message response */
	public
	StreamVerifier(TSIG tsig, TSIGRecord old) {
		key = tsig;
		verifier = new hmacSigner(key.key);
		nresponses = 0;
		lastTSIG = old;
	}

	/**
	 * Verifies a TSIG record on an incoming message that is part of a
	 * multiple message response.
	 * TSIG records must be present on the first and last messages, and
	 * at least every 100 records in between.
	 * @param m The message
	 * @param b The message in unparsed form
	 * @return The result of the verification (as an Rcode)
	 * @see Rcode
	 */
	public byte
	verify(Message m, byte [] b) {
		TSIGRecord tsig = m.getTSIG();
	
		nresponses++;

		if (nresponses == 1) {
			byte result = key.verify(m, b, lastTSIG);
			if (result == Rcode.NOERROR) {
				DataByteOutputStream dbs;
				byte [] signature;

				signature = tsig.getSignature();
				dbs = new DataByteOutputStream();
				dbs.writeShort((short)signature.length);
				verifier.addData(dbs.toByteArray());
				verifier.addData(signature);
			}
			lastTSIG = tsig;
			return result;
		}

		if (tsig != null)
			m.getHeader().decCount(Section.ADDITIONAL);
		byte [] header = m.getHeader().toWire();
		if (tsig != null)
			m.getHeader().incCount(Section.ADDITIONAL);
		verifier.addData(header);

		int len;
		if (tsig == null)
			len = b.length - header.length;
		else
			len = m.tsigstart - header.length;
		verifier.addData(b, header.length, len);

		if (tsig != null) {
			lastsigned = nresponses;
			lastTSIG = tsig;
		}
		else {
			boolean required = (nresponses - lastsigned >= 100);
			if (required)
				return Rcode.FORMERR;
			else
				return Rcode.NOERROR;
		}

		if (!tsig.getName().equals(key.name) ||
		    !tsig.getAlgorithm().equals(key.alg))
		{
			if (Options.check("verbose"))
				System.err.println("BADKEY failure");
			return Rcode.BADKEY;
		}

		DataByteOutputStream out = new DataByteOutputStream();
		long time = tsig.getTimeSigned().getTime() / 1000;
		short timeHigh = (short) (time >> 32);
		int timeLow = (int) (time);
		out.writeShort(timeHigh);
		out.writeInt(timeLow);
		out.writeShort(tsig.getFudge());
		verifier.addData(out.toByteArray());

		if (verifier.verify(tsig.getSignature()) == false) {
			if (Options.check("verbose"))
				System.err.println("BADSIG failure");
			return Rcode.BADSIG;
		}

		verifier.clear();
		DataByteOutputStream dbs = new DataByteOutputStream();
		dbs.writeShort((short)tsig.getSignature().length);
		verifier.addData(dbs.toByteArray());
		verifier.addData(tsig.getSignature());

		return Rcode.NOERROR;
	}
}

}

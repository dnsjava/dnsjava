// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;
import java.net.*;
import java.util.*;
import DNS.utils.*;

/**
 * Transaction signature handling.  This class generates and verifies
 * TSIG records on messages, which provide transaction security,
 * @see TSIGRecord
 */

public class TSIG {

/**
 * The domain name representing the HMAC-MD5 algorithm (the only supported
 * algorithm)
 */
public static final String HMAC		= "HMAC-MD5.SIG-ALG.REG.INT";

private Name name;
private byte [] key;
private hmacSigner axfrSigner = null;

/**
 * Creates a new TSIG object, which can be used to sign or verify a message.
 * @param name The name of the shared key
 * @param key The shared key's data
 */
public
TSIG(String name, byte [] key) {
	this.name = new Name(name);
	this.key = key;
}

/**
 * Generates a TSIG record for a message and adds it to the message
 * @param m The message
 * @param old If this message is a response, the TSIG from the request
 */
public void
apply(Message m, TSIGRecord old) throws IOException {
	Date timeSigned = new Date();
	short fudge = 300;
	hmacSigner h = new hmacSigner(key);

	Name alg = new Name(HMAC);

	try {
		if (old != null) {
			DataByteOutputStream dbs = new DataByteOutputStream();
			dbs.writeShort((short)old.getSignature().length);
			h.addData(dbs.toByteArray());
			h.addData(old.getSignature());
		}

		/* Digest the message */
		h.addData(m.toWire());

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
		out.writeShort(fudge);

		out.writeShort(0); /* No error */
		out.writeShort(0); /* No other data */

		h.addData(out.toByteArray());
	}
	catch (IOException e) {
		return;
	}
	Record r = new TSIGRecord(name, DClass.ANY, 0, alg, timeSigned, fudge,
				  h.sign(), m.getHeader().getID(),
				  Rcode.NOERROR, null);
	m.addRecord(Section.ADDITIONAL, r);
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
 */
public boolean
verify(Message m, byte [] b, TSIGRecord old) {
	TSIGRecord tsig = m.getTSIG();
	hmacSigner h = new hmacSigner(key);
	if (tsig == null)
		return false;
/*System.out.println("found TSIG");*/

	try {
		if (old != null && tsig.getError() == Rcode.NOERROR) {
			DataByteOutputStream dbs = new DataByteOutputStream();
			dbs.writeShort((short)old.getSignature().length);
			h.addData(dbs.toByteArray());
			h.addData(old.getSignature());
/*System.out.println("digested query TSIG");*/
		}
		m.getHeader().decCount(Section.ADDITIONAL);
		byte [] header = m.getHeader().toWire();
		m.getHeader().incCount(Section.ADDITIONAL);
		h.addData(header);

		int len = b.length - header.length;	
		len -= tsig.wireLength;
		h.addData(b, header.length, len);
/*System.out.println("digested message");*/

		DataByteOutputStream out = new DataByteOutputStream();
		tsig.getName().toWireCanonical(out);
		out.writeShort(tsig.dclass);
		out.writeInt(tsig.ttl);
		tsig.getAlg().toWireCanonical(out);
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
/*System.out.println("digested variables");*/
	}
	catch (IOException e) {
		return false;
	}

	if (axfrSigner != null) {
		DataByteOutputStream dbs = new DataByteOutputStream();
		dbs.writeShort((short)tsig.getSignature().length);
		axfrSigner.addData(dbs.toByteArray());
		axfrSigner.addData(tsig.getSignature());
	}
	if (h.verify(tsig.getSignature()))
		return true;
	else
		return false;
}

/** Prepares the TSIG object to verify an AXFR */
public void
verifyAXFRStart() {
	axfrSigner = new hmacSigner(key);
}

/**
 * Verifies a TSIG record on an incoming message that is part of an AXFR.
 * TSIG records must be present on the first and last messages, and
 * at least every 100 records in between (the last rule is not enforced).
 * @param m The message
 * @param b The message in unparsed form
 * @param old The TSIG from the AXFR request
 * @param required True if this message is required to include a TSIG.
 * @param first True if this message is the first message of the AXFR
 */
public boolean
verifyAXFR(Message m, byte [] b, TSIGRecord old,
	   boolean required, boolean first)
{
	TSIGRecord tsig = m.getTSIG();
	hmacSigner h = axfrSigner;
	
	if (first)
		return verify(m, b, old);
	try {
		if (tsig != null)
			m.getHeader().decCount(Section.ADDITIONAL);
		byte [] header = m.getHeader().toWire();
		if (tsig != null)
			m.getHeader().incCount(Section.ADDITIONAL);
		h.addData(header);

		int len = b.length - header.length;	
		if (tsig != null)
			len -= tsig.wireLength;
		h.addData(b, header.length, len);

		if (tsig == null) {
			if (required)
				return false;
			else
				return true;
		}

		DataByteOutputStream out = new DataByteOutputStream();
		long time = tsig.getTimeSigned().getTime() / 1000;
		short timeHigh = (short) (time >> 32);
		int timeLow = (int) (time);
		out.writeShort(timeHigh);
		out.writeInt(timeLow);
		out.writeShort(tsig.getFudge());
		h.addData(out.toByteArray());
	}
	catch (IOException e) {
		return false;
	}

	if (h.verify(tsig.getSignature()) == false) {
		return false;
	}

	h.clear();
	h.addData(tsig.getSignature());

	return true;
}

}

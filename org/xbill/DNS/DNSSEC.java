// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.*;

import org.xbill.DNS.utils.*;

/**
 * Constants and functions relating to DNSSEC (algorithm constants).
 * DNSSEC provides authentication for DNS information.  RRsets are
 * signed by an appropriate key, and a SIG record is added to the set.
 * A KEY record is obtained from DNS and used to validate the signature,
 * The KEY record must also be validated or implicitly trusted - to
 * validate a key requires a series of validations leading to a trusted
 * key.  The key must also be authorized to sign the data.
 * @see SIGRecord
 * @see KEYRecord
 * @see RRset
 *
 * @author Brian Wellington
 */

public class DNSSEC {

public static class Algorithm {
	public static final int RSAMD5 = 1;
	public static final int RSA = RSAMD5;
	public static final int DH = 2;
	public static final int DSA = 3;
	public static final int ECC = 4;
	public static final int RSASHA1 = 5;
	public static final int INDIRECT = 252;
	public static final int PRIVATEDNS = 253;
	public static final int PRIVATEOID = 254;

	private static StringValueTable algs = new StringValueTable();

	static {
		algs.put2(RSAMD5, "RSAMD5");
		algs.put2(DH, "DH");
		algs.put2(DSA, "DSA");
		algs.put2(ECC, "ECC");
		algs.put2(RSASHA1, "RSASHA1");
		algs.put2(INDIRECT, "INDIRECT");
		algs.put2(PRIVATEDNS, "PRIVATEDNS");
		algs.put2(PRIVATEOID, "PRIVATEOID");
	}

	/**
	 * Converts an algorithm into its textual representation
	 */
	public static String
	string(int alg) {
		if (alg < 0 || alg > 0xFF)
			throw new IllegalArgumentException("DNSSEC algorithm " +
							   alg + " is out of " +
							   "range");
		String s = algs.getString(alg);
		return (s != null) ? s : Integer.toString(alg);
	}

	/**
	 * Converts a textual representation of an algorithm into its numeric
	 * code.  Integers in the range 0..255 are also accepted.
	 * @param s The textual representation of the algorithm
	 * @return The algorithm code, or -1 on error.
	 */
	public static int
	value(String s) {
		s = s.toUpperCase();
		int alg = algs.getValue(s);
		if (alg >= 0)
			return alg;
		try {
			alg = Integer.parseInt(s);
			if (alg < 0 || alg > 0xFF)
				return -1;
			return alg;
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
}

public static final int RSAMD5 = Algorithm.RSAMD5;
public static final int RSA = Algorithm.RSAMD5;
public static final int DH = Algorithm.DH;
public static final int DSA = Algorithm.DSA;
public static final int RSASHA1 = Algorithm.RSASHA1;

public static final int Failed = -1;
public static final int Insecure = 0;
public static final int Secure = 1;

private
DNSSEC() { }

private static void
digestSIG(DataByteOutputStream out, SIGRecord sig) {
	out.writeShort(sig.getTypeCovered());
	out.writeByte(sig.getAlgorithm());
	out.writeByte(sig.getLabels());
	out.writeUnsignedInt(sig.getOrigTTL());
	out.writeInt((int) (sig.getExpire().getTime() / 1000));
	out.writeInt((int) (sig.getTimeSigned().getTime() / 1000));
	out.writeShort(sig.getFootprint());
	sig.getSigner().toWireCanonical(out);
}

/**
 * Creates an array containing fields of the SIG record and the RRsets to
 * be signed/verified.
 * @param sig The SIG record used to sign/verify the rrset.
 * @param rrset The data to be signed/verified.
 * @return The data to be cryptographically signed or verified.
 */
public static byte []
digestRRset(SIGRecord sig, RRset rrset) {
	DataByteOutputStream out = new DataByteOutputStream();
	digestSIG(out, sig);

	int size = rrset.size();
	byte [][] records = new byte[size][];

	Iterator it = rrset.rrs();
	Name name = rrset.getName();
	Name wild = null;
	if (name.labels() > sig.getLabels())
		wild = name.wild(name.labels() - sig.getLabels());
	while (it.hasNext()) {
		Record rec = (Record) it.next();
		if (wild != null)
			rec = rec.withName(wild);
		records[--size] = rec.toWireCanonical();
	}
	Arrays.sort(records);
	for (int i = 0; i < records.length; i++)
		out.writeArray(records[i]);
	return out.toByteArray();
}

/**
 * Creates an array containing fields of the SIG record and the message to
 * be signed.
 * @param sig The SIG record used to sign/verify the rrset.
 * @param msg The message to be signed/verified.
 * @param previous If this is a response, the signature from the query.
 * @return The data to be cryptographically signed or verified.
 */
public static byte []
digestMessage(SIGRecord sig, Message msg, byte [] previous) {
	DataByteOutputStream out = new DataByteOutputStream();
	digestSIG(out, sig);

	if (previous != null)
		out.writeArray(previous);
	
	msg.toWire(out);
	return out.toByteArray();
}

}

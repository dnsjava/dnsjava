// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

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

private
DNSSEC() { }

public static final byte RSAMD5 = 1;
public static final byte RSA = RSAMD5;
public static final byte DH = 2;
public static final byte DSA = 3;
public static final byte RSASHA1 = 5;

public static final byte Failed = -1;
public static final byte Insecure = 0;
public static final byte Secure = 1;

/* 
 * Creates an array containing fields of the SIG record and the RRsets to
 * be signed.  The output of this should be cryptographically signed or
 * verified.
 */
public static byte []
digestRRset(SIGRecord sig, RRset rrset) {
	DataByteOutputStream out = new DataByteOutputStream();

	out.writeShort(sig.getTypeCovered());
	out.writeByte(sig.getAlgorithm());
	out.writeByte(sig.getLabels());
	out.writeInt(sig.getOrigTTL());
	out.writeInt((int) (sig.getExpire().getTime() / 1000));
	out.writeInt((int) (sig.getTimeSigned().getTime() / 1000));
	out.writeShort(sig.getFootprint());
	sig.getSigner().toWireCanonical(out);

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

}

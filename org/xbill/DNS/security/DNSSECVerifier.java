// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.util.*;
import java.security.*;
import org.xbill.DNS.*;
import org.xbill.DNS.utils.*;

/**
 * A class that verifies DNS data using digital signatures contained in DNSSEC
 * SIG records.  DNSSECVerifier stores a set of trusted keys.  Each specific
 * verification references a cache where additional secure keys may be found.
 * @see Verifier
 * @see DNSSEC
 *
 * @author Brian Wellington
 */

public class DNSSECVerifier implements Verifier {

private Map trustedKeys;

/** Creates a new DNSSECVerifier */
public
DNSSECVerifier() {
	trustedKeys = new HashMap();
}

/** Adds the specified key to the set of trusted keys */
public synchronized void
addTrustedKey(KEYRecord key) {
	Name name = key.getName();
	List list = (List) trustedKeys.get(name);
	if (list == null)
		trustedKeys.put(name, list = new LinkedList());
	list.add(key);
}

/** Adds the specified key to the set of trusted keys */
public void
addTrustedKey(Name name, PublicKey key) {
	KEYRecord keyrec;
	keyrec = KEYConverter.buildRecord(name, DClass.IN, 0, 0,
					  KEYRecord.PROTOCOL_DNSSEC, key);
	if (keyrec != null)
		addTrustedKey(keyrec);
}

private PublicKey
findMatchingKey(Iterator it, int algorithm, int footprint) {
	while (it.hasNext()) {
		KEYRecord keyrec = (KEYRecord) it.next();
		if (keyrec.getAlgorithm() == algorithm &&
		    keyrec.getFootprint() == footprint)
			return KEYConverter.parseRecord(keyrec);
	}
	return null;
}

private synchronized PublicKey
findTrustedKey(Name name, int algorithm, int footprint) {
	List list = (List) trustedKeys.get(name);
	if (list == null)
		return null;
	return findMatchingKey(list.iterator(), algorithm, footprint);
}

private PublicKey
findCachedKey(Cache cache, Name name, int algorithm, int footprint) {
	RRset [] keysets = cache.findAnyRecords(name, Type.KEY);
	if (keysets == null)
		return null;
	RRset keys = keysets[0];
	return findMatchingKey(keys.rrs(), algorithm, footprint);
}

private PublicKey
findKey(Cache cache, Name name, int algorithm, int footprint) {
	PublicKey key = findTrustedKey(name, algorithm, footprint);
	if (key == null && cache != null)
		return findCachedKey(cache, name, algorithm, footprint);
	return key;
}

private int
verifySIG(RRset set, SIGRecord sigrec, Cache cache) {
	PublicKey key = findKey(cache, sigrec.getSigner(),
				sigrec.getAlgorithm(), sigrec.getFootprint());
	if (key == null)
		return DNSSEC.Insecure;

	Date now = new Date();
	if (now.compareTo(sigrec.getExpire()) > 0 ||
	    now.compareTo(sigrec.getTimeSigned()) < 0)
	{
		System.err.println("Outside of validity period");
		return DNSSEC.Failed;
	}
	byte [] data = DNSSEC.digestRRset(sigrec, set);

	byte [] sig;
	String algString;

	switch (sigrec.getAlgorithm()) {
		case DNSSEC.RSAMD5:
			sig = sigrec.getSignature();
			algString = "MD5withRSA";
			break;
		case DNSSEC.DSA:
			sig = DSASignature.create(sigrec);
			algString = "SHA1withDSA";
			break;
		case DNSSEC.RSASHA1:
			sig = sigrec.getSignature();
			algString = "SHA1withRSA";
			break;
		default:
			return DNSSEC.Failed;
	}

	try {
		Signature s = Signature.getInstance(algString);
		s.initVerify(key);
		s.update(data);
		return s.verify(sig) ? DNSSEC.Secure : DNSSEC.Failed;
	}
	catch (GeneralSecurityException e) {
		if (Options.check("verboseexceptions"))
			System.err.println("Signing data: " + e);
		return DNSSEC.Failed;
	}
}

/**
 * Attempts to verify an RRset.  This does not modify the set.
 * @param set The RRset to verify
 * @param cache The Cache where obtained secure keys are found (may be null)
 * @return The new security status of the set
 * @see RRset
 */
public int
verify(RRset set, Cache cache) {
	Iterator sigs = set.sigs();
	if (Options.check("verbosesec"))
		System.out.print("Verifying " + set.getName() + "/" +
				 Type.string(set.getType()) + ": ");
	if (!sigs.hasNext()) {
		if (Options.check("verbosesec"))
			System.out.println("Insecure");
		return DNSSEC.Insecure;
	}
	while (sigs.hasNext()) {
		SIGRecord sigrec = (SIGRecord) sigs.next();
		if (verifySIG(set, sigrec, cache) == DNSSEC.Secure) {
			if (Options.check("verbosesec"))
				System.out.println("Secure");
			return DNSSEC.Secure;
		}
	}
	if (Options.check("verbosesec"))
		System.out.println("Failed");
	return DNSSEC.Failed;
}

}

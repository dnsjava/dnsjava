// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS.security;

import java.io.*;
import java.security.cert.*;
import org.xbill.DNS.*;

/**
 * Routines to convert between a DNS CERT record and a Java Certificate.
 * @see CERTRecord
 * @see java.security.cert.Certificate
 *
 * @author Brian Wellington
 */


public class CERTConverter {

/** Converts a CERT record into a Certificate */
public static Certificate
parseRecord(CERTRecord r) {
	int type = r.getCertType();
	byte [] data = r.getCert();
	Certificate cert;
	try {
		switch (type) {
			case CERTRecord.PKIX: {
				CertificateFactory cf;
				ByteArrayInputStream bs;

				cf = CertificateFactory.getInstance("X.509");
				bs = new ByteArrayInputStream(data);
				cert = cf.generateCertificate(bs);
				break;
			}
			default:
				return null;
		}
		return cert;
	}
	catch (CertificateException e) {
		if (Options.check("verboseexceptions"))
			System.err.println("Cert parse exception:" + e);
		return null;
	}
}

/** Builds a CERT record from a Certificate associated with a key also in DNS */
public static CERTRecord
buildRecord(Name name, int dclass, long ttl, Certificate cert, int tag,
	    int alg)
{
	int type;
	byte [] data;

	try {
		if (cert instanceof X509Certificate) {
			type = CERTRecord.PKIX;
			data = cert.getEncoded();
		}
		else
			return null;

		return new CERTRecord(name, dclass, ttl, type, tag, alg, data);
	}
	catch (CertificateException e) {
		if (Options.check("verboseexceptions"))
			System.err.println("Cert build exception:" + e);
		return null;
	}
}

/** Builds a CERT record from a Certificate */
public static CERTRecord
buildRecord(Name name, int dclass, long ttl, Certificate cert) {
	return buildRecord(name, dclass, ttl, cert, 0, 0);
}

}

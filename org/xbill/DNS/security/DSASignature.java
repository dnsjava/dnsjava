// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS.security;

import org.xbill.DNS.*;

/**
 * Converts the DSA signature in a SIG Record to the format expected by
 * the DSA verification routines.
 *
 * @author Brian Wellington
 */

class DSASignature {

static final int ASN1_SEQ = 0x30;
static final int ASN1_INT = 0x2;

static byte []
create(SIGRecord sigrec) {
	final int len = 20;
	int n = 0;
	byte rlen, slen, seqlen;

	byte [] sigdata = sigrec.getSignature();

	rlen = len;
	if (sigdata[1] < 0)
		rlen++;

	slen = len;
	if (sigdata[1] < 0)
		slen++;

	/* 4 = 2 * (INT, value) */
	seqlen = (byte) (rlen + slen + 4);

	/* 2 = 1 * (SEQ, value) */
	byte [] array = new byte[seqlen + 2];

	array[n++] = ASN1_SEQ;
	array[n++] = (byte) seqlen;
	array[n++] = ASN1_INT;
	array[n++] = rlen;
	if (rlen > len)
		array[n++] = 0;
	for (int i = 0; i < len; i++, n++)
		array[n] = sigdata[1 + i];
	array[n++] = ASN1_INT;
	array[n++] = slen;
	if (slen > len)
		array[n++] = 0;
	for (int i = 0; i < len; i++, n++)
		array[n] = sigdata[1 + len + i];
	return array;
}

}

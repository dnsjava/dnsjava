// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import org.xbill.DNS.utils.*;

/**
 * Key - contains a cryptographic public key.  The data can be converted
 * to objects implementing java.security.interfaces.PublicKey
 * @see DNSSEC
 *
 * @author Brian Wellington
 */

public class KEYRecord extends KEYBase {

/* flags */
/** This key cannot be used for confidentiality (encryption) */
public static final int FLAG_NOCONF = 0x8000;

/** This key cannot be used for authentication */
public static final int FLAG_NOAUTH = 0x4000;

/** This key cannot be used for authentication or confidentiality */
public static final int FLAG_NOKEY = 0xC000;

/** A zone key */
public static final int OWNER_ZONE = 0x0100;

/** A host/end entity key */
public static final int OWNER_HOST = 0x0200;

/** A user key */
public static final int OWNER_USER = 0x0000;

/* protocols */
/** Key was created for use with transaction level security */
public static final int PROTOCOL_TLS = 1;

/** Key was created for use with email */
public static final int PROTOCOL_EMAIL = 2;

/** Key was created for use with DNSSEC */
public static final int PROTOCOL_DNSSEC = 3;

/** Key was created for use with IPSEC */
public static final int PROTOCOL_IPSEC = 4;

/** Key was created for use with any protocol */
public static final int PROTOCOL_ANY = 255;

KEYRecord() {}

Record
getObject() {
	return new KEYRecord();
}

/**
 * Creates a KEY Record from the given data
 * @param flags Flags describing the key's properties
 * @param proto The protocol that the key was created for
 * @param alg The key's algorithm
 * @param key Binary data representing the key
 */
public
KEYRecord(Name name, int dclass, long ttl, int flags, int proto, int alg,
	  byte [] key)
{
	super(name, Type.KEY, dclass, ttl, flags, proto, alg, key);
}

}

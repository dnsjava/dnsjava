// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

public final class Credibility {

public static final byte HINT			= 0;
public static final byte NONAUTH_ADDITIONAL	= 1;
public static final byte NONAUTH_AUTHORITY	= 1;
public static final byte AUTH_ADDITIONAL	= 1;
public static final byte NONAUTH_ANSWER		= 2;
public static final byte AUTH_NONAUTH_ANSWER	= 2;
public static final byte ZONE_TRANSFER_GLUE	= 3;
public static final byte ZONE_GLUE		= 3;
public static final byte AUTH_AUTHORITY		= 4;
public static final byte AUTH_ANSWER		= 5;
public static final byte ZONE_TRANSFER		= 6;
public static final byte ZONE			= 7;

}

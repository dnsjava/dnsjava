// Copyright (c) 1999-2003 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Constants relating to the credibility of cached data, which is based on
 * the data's source.  The constants NORMAL and ANY should be used by most
 * callers.
 * @see Cache
 * @see Section
 *
 * @author Brian Wellington
 */

public final class Credibility {

private
Credibility() {}

/** A hint or cache file on disk. */
public static final byte HINT			= 0;

/** The additional section of a response. */
public static final byte ADDITIONAL	= 1;

/** The additional section of a response. */
public static final byte GLUE		= 2;

/** The authority section of a nonauthoritative response. */
public static final byte NONAUTH_AUTHORITY	= 3;

/** The answer section of a nonauthoritative response. */
public static final byte NONAUTH_ANSWER		= 3;

/** The authority section of an authoritative response. */
public static final byte AUTH_AUTHORITY		= 4;

/** The answer section of a authoritative response. */
public static final byte AUTH_ANSWER		= 4;

/** A zone. */
public static final byte ZONE			= 5;

/** Credible data. */
public static final byte NORMAL			= 3;

/** Data not required to be credible. */
public static final byte ANY			= 1;

}

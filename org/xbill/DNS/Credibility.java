// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

/**
 * Constants relating to the credibility of cached data, which is based on
 * the data's source.  Data with credibility of 2 or greater is considered
 * credible.
 * @see Cache
 * @see Section
 *
 * @author Brian Wellington
 */

public final class Credibility {

private
Credibility() {}

/** The additional section of a nonauthoritative response.  Credibility 1. */
public static final byte NONAUTH_ADDITIONAL	= 1;

/** The authority section of a nonauthoritative response.  Credibility 1. */
public static final byte NONAUTH_AUTHORITY	= 1;

/** The additional section of an authoritative response.  Credibility 1. */
public static final byte AUTH_ADDITIONAL	= 1;

/** The answer section of a nonauthoritative response.  Credibility 2. */
public static final byte NONAUTH_ANSWER		= 2;

/**
 * The answer section of an authoritative response, but a different name than
 * the query.  Credibility 2.
 */
public static final byte AUTH_NONAUTH_ANSWER	= 2;

/** Additional data present in a zone transfer.  Credibility 3. */
public static final byte ZONE_TRANSFER_GLUE	= 3;

/** Additional data present in a zone file.  Credibility 3. */
public static final byte ZONE_GLUE		= 3;

/** The authority section of an authoritative response.  Credibility 4. */
public static final byte AUTH_AUTHORITY		= 4;

/** The answer section of a authoritative response.  Credibility 5. */
public static final byte AUTH_ANSWER		= 5;

/** A zone transfer.  Credibility 6. */
public static final byte ZONE_TRANSFER		= 6;

/** A zone file.  Credibility 7. */
public static final byte ZONE			= 7;

/** A hint or cache file on disk.  Credibility ??. */
public static final byte HINT			= ZONE_GLUE;

}

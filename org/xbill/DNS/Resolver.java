// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.net.*;

/**
 * Interface describing a resolver.
 *
 * @author Brian Wellington
 */

public interface Resolver {

/** Sets the port to communicate with on the server */
void setPort(int port);

/** Sets whether TCP connections will be sent by default */
void setTCP(boolean flag);

/** Sets whether truncated responses will be returned */
void setIgnoreTruncation(boolean flag);

/** Sets the EDNS version used on outgoing messages (only 0 is meaningful) */
void setEDNS(int level);

/** Specifies the TSIG key that messages will be signed with */
void setTSIGKey(Name name, byte [] key);

/** Specifies the TSIG key that messages will be signed with */
void setTSIGKey(String name, String key);

/**
 * Specifies the TSIG key (with the same name as the local host) that messages
 * will be signed with
 */
void setTSIGKey(String key);

/** Sets the amount of time to wait for a response before giving up */
void setTimeout(int secs);

/**
 * Sends a message, and waits for a response
 * @return The response
 */
Message send(Message query) throws IOException;

/**
 * Asynchronously sends a message, registering a listener to receive a callback.
 * Multiple asynchronous lookups can be performed in parallel.  Since the
 * callback may be invoked before the function returns, external
 * synchronization is necessary.
 * @return An identifier, which is also a parameter in the callback
 */
Object sendAsync(final Message query, final ResolverListener listener);

}

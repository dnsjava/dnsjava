// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;

/**
 * Interface describing a resolver.
 */

public interface Resolver {

/** Sets the port to communicate with on the server */
public void setPort(int port);

/** Sets whether TCP connections will be sent by default */
public void setTCP(boolean flag);

/** Sets whether truncated responses will be returned */
public void setIgnoreTruncation(boolean flag);

/** Sets the EDNS version used on outgoing messages (only 0 is meaningful) */
public void setEDNS(int level);

/** Specifies the TSIG key that messages will be signed with */
public void setTSIGKey(String name, String key);

/**
 * Specifies the TSIG key (with the same name as the local host) that messages
 * will be signed with
 */
public void setTSIGKey(String key);

/** Sets the amount of time to wait for a response before giving up */
public void setTimeout(int secs);

/**
 * Sends a message, and waits for a response
 * @return The response
 */
public Message send(Message query);

/**
 * Asynchronously sends a message, registering a listener to receive a callback.
 * Multiple asynchronous lookups can be performed in parallel.
 * @return An identifier, which is also a parameter in the callback
 */
public int sendAsync(final Message query, final ResolverListener listener);

/**
 * Sends a zone transfer message, and waits for a response
 * @return The response
 */
public Message sendAXFR(Message query);

}

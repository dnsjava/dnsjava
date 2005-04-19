// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;

/**
 * Interface describing a resolver.
 *
 * @author Brian Wellington
 */

public interface Resolver {

/**
 * Sets the port to communicate with on the server
 * @param port The port to send messages to
 */
void setPort(int port);

/**
 * Sets whether TCP connections will be sent by default
 * @param flag Indicates whether TCP connections are made
 */
void setTCP(boolean flag);

/**
 * Sets whether truncated responses will be ignored.  If not, a truncated
 * response over UDP will cause a retransmission over TCP.
 * @param flag Indicates whether truncated responses should be ignored.
 */
void setIgnoreTruncation(boolean flag);

/**
 * Sets the EDNS version used on outgoing messages.
 * @param level The EDNS level to use.  0 indicates EDNS0 and -1 indicates no
 * EDNS.
 * @throws UnsupportedOperationException An invalid level was indicated
 */
void setEDNS(int level);

/**
 * Specifies the TSIG key that messages will be signed with
 * @param key The key
 */
void setTSIGKey(TSIG key);

/**
 * Specifies the TSIG key that messages will be signed with
 * @param name The key name
 * @param key The key data
 * @deprecated Use setTSIGKey(TSIG)
 */
void setTSIGKey(Name name, byte [] key);

/**
 * Specifies the TSIG key that messages will be signed with
 * @param name The key name
 * @param key The key data, represented as a base64 encoded string.
 * @throws IllegalArgumentException The key name is an invalid name
 * @throws IllegalArgumentException The key data is improperly encoded
 * @deprecated Use setTSIGKey(TSIG)
 */
void setTSIGKey(String name, String key);

/**
 * Sets the amount of time to wait for a response before giving up.
 * @param secs The number of seconds to wait.
 */
void setTimeout(int secs);

/**
 * Sends a message and waits for a response.
 * @param query The query to send.
 * @return The response
 * @throws IOException An error occurred while sending or receiving.
 */
Message send(Message query) throws IOException;

/**
 * Asynchronously sends a message registering a listener to receive a callback
 * on success or exception.  Multiple asynchronous lookups can be performed
 * in parallel.  Since the callback may be invoked before the function returns,
 * external synchronization is necessary.
 * @param query The query to send
 * @param listener The object containing the callbacks.
 * @return An identifier, which is also a parameter in the callback
 */
Object sendAsync(final Message query, final ResolverListener listener);

}

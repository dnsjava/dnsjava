// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.EventListener;

/**
 * An interface to the asynchronous resolver.
 * @see Resolver
 */

public interface ResolverListener extends EventListener {

/**
 * The callback used by the asynchronous resolver
 * @param id The identifier returned by Resolver.sendAsync()
 * @param m The response message as returned by the Resolver
 */
public void receiveMessage(int id, Message m);

}

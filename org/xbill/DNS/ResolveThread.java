// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import java.net.*;

/**
 * A special-purpose thread used by Resolvers (both SimpleResolver and
 * ExtendedResolver) to perform asynchronous queries.
 *
 * @author Brian Wellington
 */

class ResolveThread extends Thread {

private Message query;
private Object id;
private ResolverListener listener;
private Resolver res;

/** Creates a new ResolveThread */
public
ResolveThread(Resolver res, Message query, Object id,
	      ResolverListener listener)
{
	this.res = res;
	this.query = query;
	this.id = id;
	this.listener = listener;
}


/**
 * Performs the query, and executes the callback.
 */
public void
run() {
	try {
		Message response = res.send(query);
		listener.receiveMessage(id, response);
	}
	catch (Exception e) {
		listener.handleException(id, e);
	}
}

}

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

class ResolveThread implements Runnable {

private Message query;
private Object id;
private ResolverListener listener;
private Resolver res;

/** Creates a new ResolveThread */
public
ResolveThread(Resolver _res, Message _query, Object _id,
	      ResolverListener _listener)
{
	res = _res;
	query = _query;
	id = _id;
	listener = _listener;
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

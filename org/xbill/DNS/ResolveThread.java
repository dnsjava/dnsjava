// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import org.xbill.Task.*;

/**
 * A special-purpose thread used by Resolvers (both SimpleResolver and
 * ExtendedResolver) to perform asynchronous queries.  Once started, a
 * WorkerThread never exits.  After completing a task, it blocks until
 * another task is assigned.
 */

class ResolveThread implements Runnable {

private Message query;
private int id;
private ResolverListener listener;
private Resolver res;

private static int nactive = 0;
private static Vector list = new Vector();
private static final int max = 10;
private static final long lifetime = 900 * 1000;

/** Creates a new ResolveThread */
public
ResolveThread(Resolver _res, Message _query, int _id,
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
	Message response = res.send(query);
	listener.receiveMessage(id, response);
}

}

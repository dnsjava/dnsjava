// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * A special-purpose thread used by Resolvers (both SimpleResolver and
 * ExtendedResolver) to perform asynchronous queries.
 *
 * @author Brian Wellington
 */

class ResolveThread extends Thread {

private Message query;
private Integer id;
private ResolverListener listener;
private Resolver res;

/** Creates a new ResolveThread */
public
ResolveThread(Resolver res, Message query, Integer id,
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
@Override
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

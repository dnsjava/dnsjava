// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import org.xbill.Task.*;

/**
 * An implementation of Resolver that can send queries to multiple servers,
 * sending the queries multiple times if necessary.
 * @see Resolver
 *
 * @author Brian Wellington
 */

public class ExtendedResolver implements Resolver {

private static class Resolution implements ResolverListener {
	Resolver [] resolvers;
	int [] sent;
	Object [] inprogress;
	int retries;
	int outstanding;
	boolean done;
	Message query;
	Message response;
	Exception exception;
	ResolverListener listener;

	public
	Resolution(ExtendedResolver eres, Message query) {
		List l = eres.resolvers;
		resolvers = (Resolver []) l.toArray (new Resolver[l.size()]);
		if (eres.loadBalance) {
			int nresolvers = resolvers.length;
			/*
			 * Note: this is not synchronized, since the
			 * worst thing that can happen is a random
			 * ordering, which is ok.
			 */
			int start = eres.lbStart++ % nresolvers;
			if (eres.lbStart > nresolvers)
				eres.lbStart %= nresolvers;
			if (start > 0) {
				Resolver [] shuffle = new Resolver[nresolvers];
				for (int i = 0; i <= start; i++)
					shuffle[i + start] = resolvers[i];
				for (int i = start; i < nresolvers; i++)
					shuffle[i - start] = resolvers[i];
				resolvers = shuffle;
			}
		}
		sent = new int[resolvers.length];
		inprogress = new Object[resolvers.length];
		retries = eres.retries;
		this.query = query;
	}

	public void
	send(int n) {
		sent[n]++;
		outstanding++;
		inprogress[n] = resolvers[n].sendAsync(query, this);
	}

	public Message
	start() throws IOException {
		send(0);
		synchronized (this) {
			while (!done) {
				try {
					wait();
				}
				catch (InterruptedException e) {
				}
			}
		}
		if (response != null)
			return response;
		else if (exception instanceof IOException)
			throw (IOException) exception;
		else if (exception instanceof RuntimeException)
			throw (RuntimeException) exception;
		else
			throw new RuntimeException("ExtendedResolver failure");
	}

	public void
	startAsync(ResolverListener listener) {
		this.listener = listener;
		send(0);
	}

	public void
	receiveMessage(Object id, Message m) {
		if (Options.check("verbose"))
			System.err.println("ExtendedResolver: " +
					   "received message " + id);
		synchronized (this) {
			if (done)
				return;
			response = m;
			done = true;
			if (listener == null)
				notifyAll();
			else
				listener.receiveMessage(this, response);
		}
	}

	public void
	handleException(Object id, Exception e) {
		if (Options.check("verbose"))
			System.err.println("ExtendedResolver: " +
					   "exception on message " + id);
		synchronized (this) {
			outstanding--;
			if (done)
				return;
			int n;
			for (n = 0; n < inprogress.length; n++)
				if (inprogress[n] == id)
					break;
			if (n == inprogress.length)
				return;
			boolean startnext = false;
			boolean waiting = false;
			if (sent[n] == 1 && n < resolvers.length - 1)
				startnext = true;
			if (e instanceof InterruptedIOException) {
				/* Got a timeout; retry */
				if (sent[n] < retries)
					send(n);
				if (exception == null)
					exception = e;
			} else if (e instanceof SocketException) {
				if (exception == null ||
				    exception instanceof InterruptedIOException)
					exception = e;
			} else {
				exception = e;
			}
			if (startnext)
				send(n + 1);
			if (outstanding == 0) {
				done = true;
				if (listener == null)
					notifyAll();
				else
					listener.handleException(this,
								 exception);
			}
		}
	}
}

private static final int quantum = 5;

private List resolvers;
private boolean loadBalance = false;
private int lbStart = 0;
private int retries = 3;

private void
init() {
	resolvers = new ArrayList();
}

/**
 * Creates a new Extended Resolver.  FindServer is used to locate the servers
 * for which SimpleResolver contexts should be initialized.
 * @see SimpleResolver
 * @see FindServer
 * @exception UnknownHostException Failure occured initializing SimpleResolvers
 */
public
ExtendedResolver() throws UnknownHostException {
	init();
	String [] servers = FindServer.servers();
	if (servers != null) {
		for (int i = 0; i < servers.length; i++) {
			Resolver r = new SimpleResolver(servers[i]);
			r.setTimeout(quantum);
			resolvers.add(r);
		}
	}
	else
		resolvers.add(new SimpleResolver());
}

/**
 * Creates a new Extended Resolver
 * @param servers An array of server names for which SimpleResolver
 * contexts should be initialized.
 * @see SimpleResolver
 * @exception UnknownHostException Failure occured initializing SimpleResolvers
 */
public
ExtendedResolver(String [] servers) throws UnknownHostException {
	init();
	for (int i = 0; i < servers.length; i++) {
		Resolver r = new SimpleResolver(servers[i]);
		r.setTimeout(quantum);
		resolvers.add(r);
	}
}

/**
 * Creates a new Extended Resolver
 * @param res An array of pre-initialized Resolvers is provided.
 * @see SimpleResolver
 * @exception UnknownHostException Failure occured initializing SimpleResolvers
 */
public
ExtendedResolver(Resolver [] res) throws UnknownHostException {
	init();
	for (int i = 0; i < res.length; i++)
		resolvers.add(res[i]);
}

public void
setPort(int port) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setPort(port);
}

public void
setTCP(boolean flag) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setTCP(flag);
}

public void
setIgnoreTruncation(boolean flag) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setIgnoreTruncation(flag);
}

public void
setEDNS(int level) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setEDNS(level);
}

public void
setTSIGKey(Name name, byte [] key) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setTSIGKey(name, key);
}

public void
setTSIGKey(String name, String key) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setTSIGKey(name, key);
}

public void
setTSIGKey(String key) throws UnknownHostException {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setTSIGKey(key);
}

public void
setTimeout(int secs) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.get(i)).setTimeout(secs);
}

/**
 * Sends a message and waits for a response.  Multiple servers are queried,
 * and queries are sent multiple times until either a successful response
 * is received, or it is clear that there is no successful response.
 * @param query The query to send.
 * @return The response.
 * @throws IOException An error occurred while sending or receiving.
 */
public Message
send(Message query) throws IOException {
	Resolution res = new Resolution(this, query);
	return res.start();
}

/**
 * Asynchronously sends a message to multiple servers, potentially multiple
 * times, registering a listener to receive a callback on success or exception.
 * Multiple asynchronous lookups can be performed in parallel.  Since the
 * callback may be invoked before the function returns, external
 * synchronization is necessary.
 * @param query The query to send
 * @param listener The object containing the callbacks.
 * @return An identifier, which is also a parameter in the callback
 */
public Object
sendAsync(final Message query, final ResolverListener listener) {
	Resolution res = new Resolution(this, query);
	res.startAsync(listener);
	return res;
}

/** Returns the nth resolver used by this ExtendedResolver */
public Resolver
getResolver(int n) {
	if (n < resolvers.size())
		return (Resolver)resolvers.get(n);
	return null;
}

/** Returns all resolvers used by this ExtendedResolver */
public Resolver []
getResolvers() {
	return (Resolver []) resolvers.toArray(new Resolver[resolvers.size()]);
}

/** Adds a new resolver to be used by this ExtendedResolver */
public void
addResolver(Resolver r) {
	resolvers.add(r);
}

/** Deletes a resolver used by this ExtendedResolver */
public void
deleteResolver(Resolver r) {
	resolvers.remove(r);
}

/** Sets whether the servers should be load balanced.
 * @param flag If true, servers will be tried in round-robin order.  If false,
 * servers will always be queried in the same order.
 */
public void
setLoadBalance(boolean flag) {
	loadBalance = flag;
}

/** Sets the number of retries sent to each server per query */
public void
setRetries(int retries) {
	this.retries = retries;
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;

/**
 * An implementation of Resolver that can send queries to multiple servers,
 * sending the queries multiple times if necessary.
 * @see Resolver
 */

public class ExtendedResolver implements Resolver {

class QElement {
	Message m;
	int res;

	public
	QElement(Message _m, int _res) {
		m = _m;
		res = _res;
	}
}

class Receiver implements ResolverListener {
	Vector queue;
	Hashtable idMap;

	public
	Receiver(Vector _queue, Hashtable _idMap) {
		queue = _queue;
		idMap = _idMap;
	}

	public void
	receiveMessage(int id, Message m) {
		Integer ID, R;
		int r;
		synchronized (idMap) {
			ID = new Integer(id);
			R = (Integer)idMap.get(ID);
			if (R == null)
				return;
			r = R.intValue();
			idMap.remove(ID);
		}
		synchronized (queue) {
			QElement qe = new QElement(m, r);
			queue.addElement(qe);
			queue.notify();
		}
	}
}

private static final int quantum = 20;
private Vector resolvers;

private void
init() {
	resolvers = new Vector();
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
			resolvers.addElement(r);
		}
	}
	else
		resolvers.addElement(new SimpleResolver());
}

/**
 * Creates a new Extended Resolver
 * @param servers  An array of server names for which SimpleResolver
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
		resolvers.addElement(r);
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
		resolvers.addElement(res[i]);
}

private boolean
sendTo(Message query, Receiver receiver, Hashtable idMap, int r, int q) {
	q -= r;
	Resolver res = (Resolver) resolvers.elementAt(r);
	/* Three retries */
	if (q >= 0 && q < 3) {
		synchronized (idMap) {
			int id = res.sendAsync(query, receiver);
			idMap.put(new Integer(id), new Integer(r));
		}
	}
	if (q < 6)
		return true;
	return false;
}

/** Sets the port to communicate with on the servers */
public void
setPort(int port) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setPort(port);
}

/** Sets whether TCP connections will be sent by default */
public void
setTCP(boolean flag) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTCP(flag);
}

/** Sets whether truncated responses will be returned */
public void
setIgnoreTruncation(boolean flag) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setIgnoreTruncation(flag);
}

/** Sets the EDNS version used on outgoing messages (only 0 is meaningful) */
public void
setEDNS(int level) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setEDNS(level);
}

/** Specifies the TSIG key that messages will be signed with */
public void
setTSIGKey(String name, String key) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTSIGKey(name, key);
}

/**
 * Specifies the TSIG key (with the same name as the local host) that messages
 * will be signed with
 */
public void
setTSIGKey(String key) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTSIGKey(key);
}

/** Sets the amount of time to wait for a response before giving up */
public void
setTimeout(int secs) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTimeout(secs);
}

/**
 * Sends a message, and waits for a response.  Multiple servers are queried,
 * and queries are sent multiple times until either a successful response
 * is received, or it is clear that there is no successful response.
 * @return The response
 */
public Message
send(Message query) {
	int q, r;
	Message best = null;
	boolean [] invalid = new boolean[resolvers.size()];
	Vector queue = new Vector();
	Hashtable idMap = new Hashtable();
	Receiver receiver = new Receiver(queue, idMap);

	for (q = 0; q < 20; q++) {
		Message m;
		boolean ok = false;
		synchronized (queue) {
			for (r = 0; r < resolvers.size(); r++)
				if (!invalid[r])
					ok |= sendTo(query, receiver, idMap,
						     r, q);
			if (!ok)
				break;
			try {
				queue.wait(quantum * 1000);
			}
			catch (InterruptedException e) {
			}
			if (queue.size() == 0)
				continue;
			QElement qe = (QElement) queue.firstElement();
			queue.removeElement(qe);
			m = qe.m;
			r = qe.res;
		}
		if (m == null)
			invalid[r] = true;
		else {
			byte rcode = m.getHeader().getRcode();
			if (rcode == Rcode.NOERROR)
				return m;
			else {
				if (best == null)
					best = m;
				else {
					byte bestrcode;
					bestrcode = best.getHeader().getRcode();
					if (rcode == Rcode.NXDOMAIN &&
					    bestrcode != Rcode.NXDOMAIN)
						best = m;
				}
				invalid[r] = true;
			}
		}
	}
	return best;
}

private int
uniqueID(Message m) {
	Record r = m.getQuestion();
	return (((r.getName().hashCode() & 0xFFFF) << 16) +
		(r.getType() << 8) +
		(hashCode() & 0xFF));
}

/**
 * Asynchronously sends a message, registering a listener to receive a callback
 * Multiple asynchronous lookups can be performed in parallel.
 * @return An identifier
 */
public int
sendAsync(final Message query, final ResolverListener listener) {
	final int id = uniqueID(query);
	WorkerThread.assignThread(this, query, id, listener);
	return id;
}

/**
 * Sends a zone transfer message to the first known server, and waits for a
 * response.  This should be further tuned later.
 * @return The response
 */
public
Message sendAXFR(Message query) {
	return ((Resolver)resolvers.elementAt(0)).sendAXFR(query);
}

/** Returns the i'th resolver used by this ExtendedResolver */
public Resolver
getResolver(int i) {
	if (i < resolvers.size())
		return (Resolver)resolvers.elementAt(i);
	return null;
}

/** Returns all resolvers used by this ExtendedResolver */
public Resolver []
getResolvers() {
	Resolver [] res = new Resolver[resolvers.size()];
	for (int i = 0; i < resolvers.size(); i++)
		res[i] = (Resolver) resolvers.elementAt(i);
	return res;
}

/** Adds a new resolver to be used by this ExtendedResolver */
public void
addResolver(Resolver r) {
	resolvers.addElement(r);
}

/** Deletes a resolver used by this ExtendedResolver */
public void
deleteResolver(Resolver r) {
	resolvers.removeElement(r);
}

}

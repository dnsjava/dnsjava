// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;

public class ExtendedResolver {

public class Receiver implements ResolverListener {
	public void
	receiveMessage(int id, Message m) {
		Integer ID, R;
		synchronized (idMap) {
			ID = new Integer(id);
			R = (Integer)idMap.get(ID);
			idMap.remove(ID);
		}
		synchronized (queue) {
			queue.addElement(m);
			queue.addElement(R);
			queue.notify();
		}
	}
}

static final int quantum = 15;

Resolver [] resolvers;
boolean [] invalid;
Receiver receiver;
Vector queue;
Hashtable idMap;

public
ExtendedResolver() throws UnknownHostException {
	String [] servers = FindServer.find();
	if (servers != null) {
		resolvers = new Resolver[servers.length];
		for (int i = 0; i < servers.length; i++)
			resolvers[i] = new Resolver(servers[i]);
	}
	else {
		resolvers = new Resolver[1];
		resolvers[0] = new Resolver();
	}
	invalid = new boolean[resolvers.length];
	receiver = new Receiver();
	queue = new Vector();
	idMap = new Hashtable();
}

boolean
sendTo(Message query, int r, int q) {
	if (invalid[r])
		return false;
	q -= r;
	switch (q) {
		case 0:
			resolvers[r].setTimeout(quantum);
			break;
		case 1:
			resolvers[r].setTimeout(2 * quantum);
			break;
		case 3:
			resolvers[r].setTimeout(3 * quantum);
			break;
		default:
			if (q < 6)
				return true;
			return false;
	}
	int id = resolvers[r].sendAsync(query, receiver);
	synchronized (idMap) {
		idMap.put(new Integer(id), new Integer(r));
	}
	return true;
}

public Message
send(Message query) {
	int q, r;
	Message nx = null;
	byte rcode;

	for (q = 0; q < 20; q++) {
		boolean ok = false;
		for (r = 0; r < resolvers.length; r++)
			ok |= sendTo(query, r, q);
		if (!ok)
			return null;
		Message m = null;
		synchronized (queue) {
			try {
				queue.wait((quantum+1) * 1000);
			}
			catch (InterruptedException e) {
				System.out.println("interrupted");
			}
			if (queue.size() == 0)
				continue;
			m = (Message) queue.firstElement();
			queue.removeElementAt(0);
			Integer I = (Integer) queue.firstElement();
			queue.removeElementAt(0);
			r = I.intValue();
		}
		if (m == null)
			invalid[r] = true;
		else {
			rcode = m.getHeader().getRcode();
			if (rcode == Rcode.NOERROR)
				return m;
			else {
				if (rcode == Rcode.NXDOMAIN && nx == null)
					nx = m;
				invalid[r] = true;
			}
		}
	}
	return nx;
}

public Resolver
getResolver(int i) {
	if (i < resolvers.length)
		return resolvers[i];
	return null;
}

public Resolver []
getResolvers() {
	return resolvers;
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;

public class ExtendedResolver implements Resolver {

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

SimpleResolver [] resolvers;
boolean [] invalid;
Receiver receiver;
Vector queue;
Hashtable idMap;
Vector workerthreads;

public
ExtendedResolver() throws UnknownHostException {
	String [] servers = FindServer.find();
	if (servers != null) {
		resolvers = new SimpleResolver[servers.length];
		for (int i = 0; i < servers.length; i++)
			resolvers[i] = new SimpleResolver(servers[i]);
	}
	else {
		resolvers = new SimpleResolver[1];
		resolvers[0] = new SimpleResolver();
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

public void
setPort(int port) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setPort(port);
}

public void
setTCP(boolean flag) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setTCP(flag);
}

public void
setIgnoreTruncation(boolean flag) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setIgnoreTruncation(flag);
}

public void
setEDNS(int level) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setEDNS(level);
}

public void
setTSIGKey(String name, String key) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setTSIGKey(name, key);
}

public void
setTSIGKey(String key) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setTSIGKey(key);
}

public void
setTimeout(int secs) {
	for (int i = 0; i < resolvers.length; i++)
		resolvers[i].setTimeout(secs);
}

public Message
send(Message query) {
	int q, r;
	Message best = null;
	byte rcode;

	for (q = 0; q < 20; q++) {
		boolean ok = false;
		for (r = 0; r < resolvers.length; r++)
			ok |= sendTo(query, r, q);
		if (!ok)
			break;
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
				if (best == null)
					best = m;
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
		(r.getType() + hashCode() << 8) +
		(hashCode() & 0xFF));
}

public int
sendAsync(final Message query, final ResolverListener listener) {
	final int id = uniqueID(query);
	if (workerthreads == null)
		workerthreads = new Vector();
	WorkerThread t = null;
	synchronized (workerthreads) {
		if (workerthreads.size() > 0) {
			t = (WorkerThread) workerthreads.firstElement();
			workerthreads.removeElement(t);
		}
	}
	if (t == null) {
		t = new WorkerThread(this, workerthreads);
		t.setDaemon(true);
		t.start();
	}
	synchronized (t) {
		t.assign(query, id, listener);
		t.notify();
	}
	return id;
}

public
Message sendAXFR(Message query) throws IOException {
	return resolvers[0].sendAXFR(query);
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

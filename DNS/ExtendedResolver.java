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

Vector resolvers;
Receiver receiver;
Vector queue;
Hashtable idMap;

private void
init() {
	resolvers = new Vector();
	receiver = new Receiver();
	queue = new Vector();
	idMap = new Hashtable();
}

public
ExtendedResolver() throws UnknownHostException {
	init();
	String [] servers = FindServer.find();
	if (servers != null) {
		for (int i = 0; i < servers.length; i++)
			resolvers.addElement(new SimpleResolver(servers[i]));
	}
	else
		resolvers.addElement(new SimpleResolver());
}

public
ExtendedResolver(String [] servers) throws UnknownHostException {
	init();
	for (int i = 0; i < servers.length; i++)
		resolvers.addElement(new SimpleResolver(servers[i]));
}

public
ExtendedResolver(Resolver [] res) throws UnknownHostException {
	init();
	for (int i = 0; i < res.length; i++)
		resolvers.addElement(res[i]);
}

boolean
sendTo(Message query, int r, int q) {
	q -= r;
	Resolver res = (Resolver) resolvers.elementAt(r);
	switch (q) {
		case 0:
			res.setTimeout(quantum);
			break;
		case 1:
			res.setTimeout(2 * quantum);
			break;
		case 3:
			res.setTimeout(3 * quantum);
			break;
		default:
			if (q < 6)
				return true;
			return false;
	}
	synchronized (idMap) {
		int id = res.sendAsync(query, receiver);
		idMap.put(new Integer(id), new Integer(r));
	}
	return true;
}

public void
setPort(int port) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setPort(port);
}

public void
setTCP(boolean flag) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTCP(flag);
}

public void
setIgnoreTruncation(boolean flag) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setIgnoreTruncation(flag);
}

public void
setEDNS(int level) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setEDNS(level);
}

public void
setTSIGKey(String name, String key) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTSIGKey(name, key);
}

public void
setTSIGKey(String key) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTSIGKey(key);
}

public void
setTimeout(int secs) {
	for (int i = 0; i < resolvers.size(); i++)
		((Resolver)resolvers.elementAt(i)).setTimeout(secs);
}

public Message
send(Message query) {
	int q, r;
	Message best = null;
	byte rcode;
	boolean [] invalid = new boolean[resolvers.size()];

	for (q = 0; q < 20; q++) {
		Message m;
		synchronized (queue) {
			boolean ok = false;
			for (r = 0; r < resolvers.size(); r++)
				if (!invalid[r])
					ok |= sendTo(query, r, q);
			if (!ok)
				break;
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
	WorkerThread.assignThread(this, query, id, listener);
	return id;
}

public
Message sendAXFR(Message query) {
	return ((Resolver)resolvers.elementAt(0)).sendAXFR(query);
}

public Resolver
getResolver(int i) {
	if (i < resolvers.size())
		return (Resolver)resolvers.elementAt(i);
	return null;
}

public Resolver []
getResolvers() {
	Resolver [] res = new Resolver[resolvers.size()];
	for (int i = 0; i < resolvers.size(); i++)
		res[i] = (Resolver) resolvers.elementAt(i);
	return res;
}

public void
addResolver(Resolver r) {
	resolvers.addElement(r);
}

public void
deleteResolver(Resolver r) {
	resolvers.removeElement(r);
}

}

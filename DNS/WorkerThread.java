// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

class WorkerThread extends Thread {

private Message query;
private int id;
private ResolverListener listener;
private Resolver resolver;

private static Vector list = new Vector();

WorkerThread() {
	setDaemon(true);
	start();
}

static WorkerThread
getThread() {
	WorkerThread t;
	synchronized (list) {
		if (list.size() > 0) {
			t = (WorkerThread) list.firstElement();
			list.removeElement(t);
		}
	}
	t = new WorkerThread();
	return t;
}

public static void
assignThread(Resolver _res, Message _query, int _id,
	     ResolverListener _listener)
{
	WorkerThread t = getThread();
	t.resolver = _res;
	t.query = _query;
	t.id = _id;
	t.listener = _listener;
	Thread.yield();
	synchronized (t) {
		t.notify();
	}
}

public void
run() {
	while (true) {
		synchronized (this) {
			try {
				wait();
			}
			catch (InterruptedException e) {
			}
		}
		Message response = resolver.send(query);
		listener.receiveMessage(id, response);
		synchronized (list) {
			list.addElement(this);
		}
	}
}

}

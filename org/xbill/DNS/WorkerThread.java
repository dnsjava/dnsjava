// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.*;
import java.io.*;
import java.net.*;
import DNS.utils.*;

/**
 * A special-purpose thread used by Resolvers (both SimpleResolver and
 * ExtendedResolver) to perform asynchronous queries.  Once started, a
 * WorkerThread never exits.  After completing a task, it blocks until
 * another task is assigned.
 */

class WorkerThread extends Thread {

private Message query;
private int id;
private ResolverListener listener;
private Resolver res;

private static int nactive = 0;
private static Vector list = new Vector();
private static final int max = 10;
private static final long lifetime = 900 * 1000;

WorkerThread() {
	setDaemon(true);
}

/**
 * Obtains a WorkerThread to which a task can be assigned.  If an idle
 * WorkerThread is present, it is removed from the idle list and returned.
 * If not, and the maximum number of WorkerThreads has not been reached,
 * a new WorkerThread is created.  If the maximum number has been reached,
 * this blocks until a WorkerThread is free.
 */
static WorkerThread
getThread() {
	WorkerThread t;
	synchronized (list) {
		if (list.size() > 0) {
			t = (WorkerThread) list.firstElement();
			list.removeElement(t);
		}
		else if (nactive == max) {
			while (true) {
				try {
					list.wait();
				}
				catch (InterruptedException e) {
				}
				if (list.size() == 0)
					continue;
				t = (WorkerThread) list.firstElement();
				list.removeElement(t);
				break;
			}
		}
		else
			t = new WorkerThread();
		nactive++;
	}
	return t;
}

/**
 * Assigns a task to a WorkerThread
 * @param res The resolver using the WorkerThread
 * @param query The query to send
 * @param id The id of the query
 * @param listener The object registered to receive a callback
 */
public static void
assignThread(Resolver _res, Message _query, int _id,
	     ResolverListener _listener)
{
	WorkerThread t = getThread();
	t.res = _res;
	t.query = _query;
	t.id = _id;
	t.listener = _listener;
	synchronized (t) {
		if (!t.isAlive())
			t.start();
		t.notify();
	}
}

/** Performs the task and executes the callback */
public void
run() {
	while (true) {
		setName(res.getClass() + ": " + query.getQuestion().getName());
		Message response = res.send(query);
		listener.receiveMessage(id, response);
		setName("idle thread");
		synchronized (list) {
			list.addElement(this);
			if (nactive == max)
				list.notify();
			nactive--;
		}
		res = null;
		synchronized (this) {
			try {
				wait(lifetime);
			}
			catch (InterruptedException e) {
			}
			if (res == null)
				return;
		}
	}
}

}

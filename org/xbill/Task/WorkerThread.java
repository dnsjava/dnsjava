// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.Task;

import java.util.*;

/**
 * An extension of a Thread that uses threads from a pool, rather than
 * allocating a new thread for each assigned task.
 */

public class WorkerThread extends Thread {

private Runnable task;
private String name;

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
 * @param task The task to be run
 * @param name The name of the task
 */
public static void
assignThread(Runnable task, String name) {
	WorkerThread t = getThread();
	t.task = task;
	t.name = name;
	synchronized (t) {
		if (!t.isAlive())
			t.start();
		else
			t.notify();
	}
}

/** Performs the task */
public void
run() {
	while (true) {
		
		setName(name);
		task.run();
		setName("idle thread");
		synchronized (list) {
			list.addElement(this);
			if (nactive == max)
				list.notify();
			nactive--;
		}
		task = null;
		synchronized (this) {
			try {
				wait(lifetime);
			}
			catch (InterruptedException e) {
			}
			if (task == null) {
				list.removeElement(this);
				return;
			}
		}
	}
}

}

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
private Vector list;

public
WorkerThread(Resolver res, Vector threads) {
	resolver = res;
	list = threads;
}

public void
assign(Message _query, int _id, ResolverListener _listener) {
	query = _query;
	id = _id;
	listener = _listener;
}

public void
run() {
	while (true) {
		Message response = null;
		response = resolver.send(query);
		listener.receiveMessage(id, response);
		synchronized (list) {
			list.addElement(this);
		}
		synchronized (this) {
			try {
				wait();
			}
			catch (InterruptedException e) {
			}
		}
	}
}

}

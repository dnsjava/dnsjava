// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import org.xbill.DNS.utils.hexdump;

class Client {

protected long endTime;
protected SelectionKey key;

protected
Client(SelectableChannel channel, long endTime) throws IOException {
	boolean done = false;
	Selector selector = null;
	try {
		selector = Selector.open();
		channel.configureBlocking(false);
		key = channel.register(selector, 0);
		done = true;
	}
	finally {
		if (!done && selector != null)
			selector.close();
		if (!done)
			channel.close();
	}
}

static protected void
blockUntil(SelectionKey key, long endTime) throws IOException {
	long timeout = endTime - System.currentTimeMillis();
	if (timeout < 0 || key.selector().select(timeout) == 0)
		throw new SocketTimeoutException();
}

static protected void
verboseLog(String prefix, byte [] data) {
	if (Options.check("verbosemsg"))
		System.err.println(hexdump.dump(prefix, data));
}

void
cleanup() throws IOException {
	key.selector().close();
	key.channel().close();
}

}

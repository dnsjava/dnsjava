// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

final class UDPClient extends Client{

private
UDPClient() {}

static SelectionKey
initialize() throws IOException {
	return initializeHelper(DatagramChannel.open());
}

static void
connect(SelectionKey key, SocketAddress addr, long endTime) throws IOException {
	DatagramChannel channel = (DatagramChannel) key.channel();
	channel.connect(addr);
}

static void
send(SelectionKey key, byte [] data, long endTime) throws IOException {
	DatagramChannel channel = (DatagramChannel) key.channel();
	verboseLog("UDP write", data);
	channel.write(ByteBuffer.wrap(data));
}

static byte []
recv(SelectionKey key, int max, long endTime) throws IOException {
	DatagramChannel channel = (DatagramChannel) key.channel();
	byte [] temp = new byte[max];
	key.interestOps(SelectionKey.OP_READ);
	try {
		while (!key.isReadable())
			blockUntil(key, endTime);
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
	long ret = channel.read(ByteBuffer.wrap(temp));
	if (ret <= 0)
		throw new EOFException();
	int len = (int) ret;
	byte [] data = new byte[len];
	System.arraycopy(temp, 0, data, 0, len);
	verboseLog("UDP read", data);
	return data;
}

static byte []
sendrecv(SocketAddress addr, byte [] data, int max, long endTime)
throws IOException
{
	SelectionKey key = initialize();
	try {
		connect(key, addr, endTime);
		send(key, data, endTime);
		return recv(key, max, endTime);
	}
	finally {
		cleanup(key);
	}
}

}

// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

final class UDPClient extends Client {

public
UDPClient(long endTime) throws IOException {
	super(DatagramChannel.open(), endTime);
}

void
connect(SocketAddress addr) throws IOException {
	DatagramChannel channel = (DatagramChannel) key.channel();
	channel.connect(addr);
}

void
send(byte [] data) throws IOException {
	DatagramChannel channel = (DatagramChannel) key.channel();
	verboseLog("UDP write", data);
	channel.write(ByteBuffer.wrap(data));
}

byte []
recv(int max) throws IOException {
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
	UDPClient client = new UDPClient(endTime);
	try {
		client.connect(addr);
		client.send(data);
		return client.recv(max);
	}
	finally {
		client.cleanup();
	}
}

}

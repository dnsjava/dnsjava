// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;

final class TCPClient extends Client {

private
TCPClient() {}

static SelectionKey
initialize() throws IOException {
	return initializeHelper(SocketChannel.open());
}

static void
connect(SelectionKey key, SocketAddress addr, long endTime) throws IOException {
	SocketChannel channel = (SocketChannel) key.channel();
	if (channel.connect(addr))
		return;
	key.interestOps(SelectionKey.OP_CONNECT);
	try {
		while (!channel.finishConnect()) {
			if (!key.isConnectable())
				blockUntil(key, endTime);
		}
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
}

static void
send(SelectionKey key, byte [] data, long endTime) throws IOException {
	SocketChannel channel = (SocketChannel) key.channel();
	verboseLog("TCP write", data);
	byte [] lengthArray = new byte[2];
	lengthArray[0] = (byte)(data.length >>> 8);
	lengthArray[1] = (byte)(data.length & 0xFF);
	ByteBuffer [] buffers = new ByteBuffer[2];
	buffers[0] = ByteBuffer.wrap(lengthArray);
	buffers[1] = ByteBuffer.wrap(data);
	int nsent = 0;
	key.interestOps(SelectionKey.OP_WRITE);
	try {
		while (nsent < data.length + 2) {
			if (key.isWritable()) {
				long n = channel.write(buffers);
				if (n < 0)
					throw new EOFException();
				nsent += (int) n;
			} else
				blockUntil(key, endTime);
		}
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
}

static private byte []
_recv(SelectionKey key, int length, long endTime) throws IOException {
	SocketChannel channel = (SocketChannel) key.channel();
	int nrecvd = 0;
	byte [] data = new byte[length];
	ByteBuffer buffer = ByteBuffer.wrap(data);
	key.interestOps(SelectionKey.OP_READ);
	try {
		while (nrecvd < length) {
			if (key.isReadable()) {
				long n = channel.read(buffer);
				if (n < 0)
					throw new EOFException();
				nrecvd += (int) n;
			} else
				blockUntil(key, endTime);
		}
	}
	finally {
		if (key.isValid())
			key.interestOps(0);
	}
	return data;
}

static byte []
recv(SelectionKey key, long endTime) throws IOException {
	byte [] buf = _recv(key, 2, endTime);
	int length = ((buf[0] & 0xFF) << 8) + (buf[1] & 0xFF);
	byte [] data = _recv(key, length, endTime);
	verboseLog("TCP read", data);
	return data;
}

static byte []
sendrecv(SocketAddress addr, byte [] data, long endTime) throws IOException {
	SelectionKey key = initialize();
	try {
		connect(key, addr, endTime);
		send(key, data, endTime);
		return recv(key, endTime);
	}
	finally {
		cleanup(key);
	}
}

}

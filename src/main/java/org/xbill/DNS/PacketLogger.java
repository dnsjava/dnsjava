package org.xbill.DNS;

import java.net.SocketAddress;

/**
 * Custom logger that can log all the packets that were send or received.
 *
 * @author Damian Minkov
 */
public interface PacketLogger {
  void log(String prefix, SocketAddress local, SocketAddress remote, byte[] data);
}

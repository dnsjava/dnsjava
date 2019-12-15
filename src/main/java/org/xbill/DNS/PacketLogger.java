package org.xbill.DNS;

import java.net.SocketAddress;

/**
 * Custom logger that can log all packets that were sent or received.
 *
 * @author Damian Minkov
 */
public interface PacketLogger {
  /**
   * Logs data (usually a DNS message in wire format) that was sent or received within the dnsjava
   * library.
   *
   * <p>This method can be invoked concurrently from any thread.
   *
   * @param prefix a note of where the package originated, e.g. {@code TCP read}.
   * @param local the local (i.e. this pc) socket address of the communication channel.
   * @param remote the remote (i.e. the server) socket address of the communication channel.
   * @param data the transferred data, usually a complete DNS message.
   */
  void log(String prefix, SocketAddress local, SocketAddress remote, byte[] data);
}

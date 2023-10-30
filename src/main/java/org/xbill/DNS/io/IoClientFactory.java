// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.io;

import org.xbill.DNS.SimpleResolver;

/**
 * Interface for creating the TCP/UDP factories necessary for the {@link SimpleResolver}.
 *
 * @since 3.6
 */
public interface IoClientFactory {
  /**
   * Create or return a cached/reused instance of the TCP resolver that should be used to send DNS
   * data over the wire to the remote target. <br>
   * It is the responsibility of this method to manage pooling or connection reuse. This method is
   * called right before the connection is made every time the {@link SimpleResolver} is called. The
   * implementer of this method should be aware and choose how to pool or reuse connections.
   *
   * @return an instance of the tcp resolver client
   */
  TcpIoClient createOrGetTcpClient();

  /**
   * Create or return a cached/reused instance of the UDP resolver that should be used to send DNS
   * data over the wire to the remote target.
   *
   * @return an instance of the udp resolver client
   */
  UdpIoClient createOrGetUdpClient();
}

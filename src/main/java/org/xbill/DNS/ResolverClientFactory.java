// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Interface for creating the TCP/UDP factories necessary for the simple resolver.
 *
 * @since 3.6
 */
public interface ResolverClientFactory {

  /**
   * Create or return a cached/reused instance of the TCP resolver that should be used to send UDP
   * over the wire to the remote target. <br>
   * It is the responsibility of this method to manage pooling or connection reuse. This method is
   * called right before the connection is made every time the simple resolver is called. The
   * implementer of this method should be aware and choose how to pool or reuse connections.
   *
   * @since 3.6
   * @return an instance of the tcp resolver client
   */
  TcpResolverClient createOrGetTcpClient();

  /**
   * Create or return a cached/reused instance of the UDP resolver that should be used to send UDP
   * over the wire to the remote target.
   *
   * @since 3.6
   * @return an instance of the udp resolver client
   */
  UdpResolverClient createOrGetUdpClient();
}

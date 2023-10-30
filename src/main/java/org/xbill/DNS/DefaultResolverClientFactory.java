// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Serves as a default implementation that is used by the SimpleResolver unless otherwise configured
 * by the end-user. This preserves the default behavior (to use the built-in NIO clients) while
 * allowing flexibility at the point of use.
 *
 * @since 3.6
 */
public class DefaultResolverClientFactory implements ResolverClientFactory {

  /**
   * Shared instance because it only serves as a bridge to the static NIO classes and does not need
   * to be different per class.
   */
  private static final DefaultResolverClient RESOLVER_CLIENT = new DefaultResolverClient();

  @Override
  public TcpResolverClient createOrGetTcpClient() {
    return RESOLVER_CLIENT;
  }

  @Override
  public UdpResolverClient createOrGetUdpClient() {
    return RESOLVER_CLIENT;
  }
}

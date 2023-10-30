// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.io;

import org.xbill.DNS.DefaultIoClient;
import org.xbill.DNS.SimpleResolver;

/**
 * Serves as a default implementation that is used by the {@link SimpleResolver}, unless otherwise
 * configured. This preserves the default behavior (to use the built-in NIO clients) while allowing
 * flexibility at the point of use.
 *
 * @since 3.6
 */
public class DefaultIoClientFactory implements IoClientFactory {
  /**
   * Shared instance because it only serves as a bridge to the static NIO classes and does not need
   * to be different per class.
   */
  private static final DefaultIoClient RESOLVER_CLIENT = new DefaultIoClient();

  @Override
  public TcpIoClient createOrGetTcpClient() {
    return RESOLVER_CLIENT;
  }

  @Override
  public UdpIoClient createOrGetUdpClient() {
    return RESOLVER_CLIENT;
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.config;

import java.net.InetSocketAddress;
import java.util.List;
import org.xbill.DNS.Name;

public interface ResolverConfigProvider {
  /** Initializes the servers, search paths, etc. */
  void initialize() throws InitializationException;

  /** Returns all located servers, which may be empty. */
  List<InetSocketAddress> servers();

  /** Returns all entries in the located search path, which may be empty. */
  List<Name> searchPaths();

  /**
   * Gets the threshold for the number of dots which must appear in a name before it is considered
   * absolute. If the interface implementation does not override this, the default implementation
   * returns 1.
   */
  default int ndots() {
    return 1;
  }

  /** Determines if this provider is enabled. */
  default boolean isEnabled() {
    return true;
  }
}

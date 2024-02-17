// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import org.xbill.DNS.Name;

/**
 * Thrown to indicate that no data is associated with the given name, as indicated by the {@link
 * org.xbill.DNS.Rcode#NXDOMAIN} response code as specified in RF2136 Section 2.2.
 *
 * @since 3.4
 */
public class NoSuchDomainException extends LookupFailedException {
  public NoSuchDomainException(Name name, int type) {
    this(name, type, false);
  }

  /**
   * @since 3.6
   */
  NoSuchDomainException(Name name, int type, boolean isAuthenticated) {
    super(null, null, name, type, isAuthenticated);
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import org.xbill.DNS.Name;

/**
 * Thrown to indicate that records of the name and type queried does not exist, corresponding to the
 * {@link org.xbill.DNS.Rcode#NXRRSET} return code as specified in RFC 2136, Section 2.2.
 *
 * @since 3.4
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2136#section-2">RFC 2136</a>
 */
public class NoSuchRRSetException extends LookupFailedException {
  public NoSuchRRSetException(Name name, int type) {
    this(name, type, false);
  }

  NoSuchRRSetException(Name name, int type, boolean isAuthenticated) {
    super(null, null, name, type, isAuthenticated);
  }
}

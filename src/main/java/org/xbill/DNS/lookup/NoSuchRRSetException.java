// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import org.xbill.DNS.Name;

/**
 * Thrown to indicate that records of the name and type queried does not exist, corresponding to the
 * NXRRSET return code as specified in RFC2136 Section 2.2.
 */
public class NoSuchRRSetException extends LookupFailedException {
  public NoSuchRRSetException(Name name, int type) {
    super(name, type);
  }
}

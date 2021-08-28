// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

/**
 * Thrown if the lookup results in too many CNAME and/or DNAME indirections. This would be the case
 * for example if two CNAME records point to each other.
 */
public class RedirectOverflowException extends LookupFailedException {
  /** @deprecated do not use, this class is meant for internal dnsjava usage only. */
  @Deprecated
  public RedirectOverflowException(String message) {
    super(message);
  }

  RedirectOverflowException(int maxRedirects) {
    super("Refusing to follow more than " + maxRedirects + " redirects");
  }
}

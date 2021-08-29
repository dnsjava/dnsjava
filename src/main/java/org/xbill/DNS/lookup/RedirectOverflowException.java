// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

import lombok.Getter;

/**
 * Thrown if the lookup results in too many CNAME and/or DNAME indirections. This would be the case
 * for example if two CNAME records point to each other.
 */
public class RedirectOverflowException extends LookupFailedException {
  @Getter private final int maxRedirects;

  /** @deprecated Use {@link RedirectOverflowException#RedirectOverflowException(int)}. */
  @Deprecated
  public RedirectOverflowException(String message) {
    super(message);
    maxRedirects = 0;
  }

  public RedirectOverflowException(int maxRedirects) {
    super("Refusing to follow more than " + maxRedirects + " redirects");
    this.maxRedirects = maxRedirects;
  }
}

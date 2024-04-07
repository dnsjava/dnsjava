// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import lombok.Getter;

/**
 * Thrown if the lookup results in too many CNAME and/or DNAME indirections. This would be the case
 * for example if two CNAME records point to each other.
 *
 * @since 3.4
 */
public class RedirectOverflowException extends LookupFailedException {
  @Getter private final int maxRedirects;

  /**
   * Do not use.
   *
   * @deprecated Use {@link RedirectOverflowException#RedirectOverflowException(int)}.
   */
  @Deprecated
  public RedirectOverflowException(String message) {
    super(message);
    maxRedirects = 0;
  }

  /**
   * @param maxRedirects Informational, indicates the after how many redirects following was
   *     aborted.
   * @since 3.4.2
   */
  public RedirectOverflowException(int maxRedirects) {
    super("Refusing to follow more than " + maxRedirects + " redirects");
    this.maxRedirects = maxRedirects;
  }

  RedirectOverflowException(String message, int maxRedirects) {
    super(message);
    this.maxRedirects = maxRedirects;
  }
}

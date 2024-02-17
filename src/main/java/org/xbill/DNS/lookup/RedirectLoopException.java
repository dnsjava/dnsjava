// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

/**
 * Thrown if the lookup results in a loop of CNAME and/or DNAME indirections.
 *
 * @since 3.6
 */
public class RedirectLoopException extends RedirectOverflowException {
  public RedirectLoopException(int maxRedirects) {
    super("Detected a redirect loop", maxRedirects);
  }
}

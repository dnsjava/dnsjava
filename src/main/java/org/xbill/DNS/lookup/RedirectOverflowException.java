// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.lookup;

/**
 * Thrown if the lookup results in too many CNAME and/or DNAME indirections. This would be the case
 * for example if two CNAME records point to each other.
 */
public class RedirectOverflowException extends LookupFailedException {
  public RedirectOverflowException(String message) {
    super(message);
  }
}

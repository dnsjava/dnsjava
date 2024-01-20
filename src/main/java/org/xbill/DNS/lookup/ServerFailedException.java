// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import lombok.Getter;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

/**
 * Represents a server failure. The upstream server responding to the request returned a {@link
 * org.xbill.DNS.Rcode#SERVFAIL} status.
 */
public class ServerFailedException extends LookupFailedException {
  /**
   * An extended error code explaining why the server failed to return a result. May be {@code
   * null}.
   *
   * @since 3.6
   */
  @Getter private final ExtendedErrorCodeOption extendedRcode;

  public ServerFailedException() {
    extendedRcode = null;
  }

  /**
   * Creates a new instance of this class.
   *
   * @param name The name in the query that caused the failure.
   * @param type The type in the query that caused the failure.
   * @since 3.6
   */
  public ServerFailedException(Name name, int type) {
    super(name, type);
    extendedRcode = null;
  }

  /**
   * Creates a new instance of this class.
   *
   * @param name The name in the query that caused the failure.
   * @param type The type in the query that caused the failure.
   * @param extendedRcode An extended error code explaining why the server failed to return a
   *     result.
   * @since 3.6
   */
  public ServerFailedException(Name name, int type, ExtendedErrorCodeOption extendedRcode) {
    super(
        "Lookup for " + name + "/" + Type.string(type) + " failed with " + extendedRcode.getText(),
        name,
        type);
    this.extendedRcode = extendedRcode;
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec.validator;

import org.xbill.DNS.dnssec.SMessage;
import org.xbill.DNS.dnssec.SecurityStatus;

/**
 * Codes for DNSSEC security statuses along with a reason why the status was determined.
 *
 * @since 3.5
 */
class JustifiedSecStatus {
  SecurityStatus status;
  String reason;

  /**
   * Creates a new instance of this class.
   *
   * @param status The security status.
   * @param reason The reason why the status was determined.
   */
  JustifiedSecStatus(SecurityStatus status, String reason) {
    this.status = status;
    this.reason = reason;
  }

  /**
   * Applies this security status to a response message.
   *
   * @param response The response to which to apply this status.
   */
  void applyToResponse(SMessage response) {
    response.setStatus(this.status, this.reason);
  }
}

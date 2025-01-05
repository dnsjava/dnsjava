// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import lombok.Getter;

/** Indicates that converting a {@link Message} to wire format exceeded the maximum length. */
@Getter
public final class MessageSizeExceededException extends Exception {
  /** Gets the maximum allowed size (in bytes). */
  private final int maxSize;

  MessageSizeExceededException(int maxSize) {
    super("Message size would exceed the allowed maximum of " + maxSize + " bytes");
    this.maxSize = maxSize;
  }
}

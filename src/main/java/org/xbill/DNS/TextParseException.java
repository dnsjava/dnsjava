// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2002-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * An exception thrown when unable to parse text.
 *
 * @author Brian Wellington
 */
public class TextParseException extends IOException {

  public TextParseException() {
    super();
  }

  public TextParseException(String s) {
    super(s);
  }

  /**
   * Create an instance with preformatted message.
   *
   * @since 3.5
   */
  public TextParseException(String name, String message) {
    super("'" + name + "': " + message);
  }

  /**
   * Create an instance with preformatted message and inner exception.
   *
   * @since 3.5
   */
  public TextParseException(String name, String message, Exception inner) {
    super("'" + name + "': " + message, inner);
  }
}

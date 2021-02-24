// SPDX-License-Identifier: BSD-2-Clause
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
}

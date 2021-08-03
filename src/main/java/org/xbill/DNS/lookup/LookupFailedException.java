// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import org.xbill.DNS.Name;

/** A base class for all types of things that might fail when making a DNS lookup. */
public class LookupFailedException extends RuntimeException {
  private final Name name;
  private final int type;

  public LookupFailedException() {
    super();
    name = null;
    type = 0;
  }

  public LookupFailedException(String message) {
    super(message);
    name = null;
    type = 0;
  }

  /**
   * Construct a LookupFailedException that also specifies the name and type of the lookup that
   * failed.
   *
   * @param name the name that caused the failure.
   * @param type the type that caused the failure.
   */
  public LookupFailedException(Name name, int type) {
    this.name = name;
    this.type = type;
  }

  /** Gets the Name being looked up when this failure occurred. */
  public Name getName() {
    return name;
  }

  /** Gets the {@link org.xbill.DNS.Type} being looked up when this failure occurred. */
  public int getType() {
    return type;
  }
}

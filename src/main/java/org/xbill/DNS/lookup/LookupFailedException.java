// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import lombok.AccessLevel;
import lombok.Getter;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

/**
 * A base class for all types of things that might fail when making a DNS lookup.
 *
 * @since 3.4
 */
public class LookupFailedException extends RuntimeException {
  private final Name name;
  private final int type;

  @Getter(AccessLevel.PACKAGE)
  private final boolean isAuthenticated;

  public LookupFailedException() {
    this(null, null, null, 0, false);
  }

  public LookupFailedException(String message) {
    this(message, null, null, 0, false);
  }

  LookupFailedException(String message, Throwable inner) {
    this(message, inner, null, 0, false);
  }

  /**
   * Construct a LookupFailedException that also specifies the name and type of the lookup that
   * failed.
   *
   * @param name the name that caused the failure.
   * @param type the type that caused the failure.
   */
  public LookupFailedException(Name name, int type) {
    this("Lookup for " + name + "/" + Type.string(type) + " failed", name, type);
  }

  /**
   * Construct a LookupFailedException with a custom message that also specifies the name and type
   * of the lookup that failed.
   *
   * @param name the name that caused the failure.
   * @param type the type that caused the failure.
   * @since 3.6
   */
  public LookupFailedException(String message, Name name, int type) {
    this(message, null, name, type, false);
  }

  LookupFailedException(
      String message, Throwable inner, Name name, int type, boolean isAuthenticated) {
    super(message, inner);
    this.name = name;
    this.type = type;
    this.isAuthenticated = isAuthenticated;
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

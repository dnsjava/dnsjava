package org.xbill.DNS.exceptions;

/** A base class for all types of things that might fail when making a DNS lookup. */
public class LookupFailedException extends RuntimeException {
  public LookupFailedException() {
    super();
  }

  public LookupFailedException(String message) {
    super(message);
  }
}

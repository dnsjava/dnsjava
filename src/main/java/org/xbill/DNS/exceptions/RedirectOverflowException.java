package org.xbill.DNS.exceptions;

public class RedirectOverflowException extends LookupFailedException {
  public RedirectOverflowException(String message) {
    super(message);
  }
}

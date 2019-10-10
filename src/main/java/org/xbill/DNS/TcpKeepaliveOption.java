package org.xbill.DNS;

import java.io.IOException;


/**
 * TCP Keepalive EDNS0 Option, as defined in https://tools.ietf.org/html/rfc7828
 *
 * @see OPTRecord
 * @author Klaus Malorny
 */
public class TcpKeepaliveOption extends EDNSOption {

  /** flag whether the timeout has been provided */
  private boolean hasTimeout;

  /** the timeout in 100ms units */
  private int timeout;


  /**
   * Constructor for an option with no timeout
   */
  public TcpKeepaliveOption() {
    super(EDNSOption.Code.TCP_KEEPALIVE);
    hasTimeout = false;
  }


  /**
   * Constructor for an option with a given timeout.
   *
   * @param t   the timeout time in 100ms units, may not be negative or
   *            larger than 65535
   */
  public TcpKeepaliveOption(int t) {
    super(EDNSOption.Code.TCP_KEEPALIVE);
    if (t < 0 || t > 65535)
      throw new IllegalArgumentException("timeout must be betwee 0 and 65535");
    hasTimeout = true;
    timeout = t;
  }


  /**
   * Returns whether the option contains a timeout.
   *
   * @return   {@code true} if the option contains a timeout
   */
  public boolean hasTimeout() {
    return hasTimeout;
  }


  /**
   * Returns the timeout.
   *
   * @return    the timeout in 100ms units
   */
  public int getTimeout()
  {
    if (!hasTimeout)
      throw new IllegalStateException("option does not have the timeout set");
    return timeout;
  }


  /**
   * Converts the wire format of an EDNS Option (the option data only) into the type-specific
   * format.
   *
   * @param in The input stream.
   */
  @Override
  void optionFromWire(DNSInput in) throws IOException {
    int length = in.remaining();

    switch (length) {
      case 0:
        hasTimeout = false;
        break;
      case 2:
        hasTimeout = true;
        timeout = in.readU16();
        break;
      default:
        throw new WireParseException("invalid length (" + length + 
          ") of the data in the edns_tcp_keepalive option");
    }
  }


  /**
   * Converts an EDNS Option (the type-specific option data only) into wire format.
   *
   * @param out The output stream.
   */
  @Override
  void optionToWire(DNSOutput out) {
    if (hasTimeout)
      out.writeU16(timeout);
  }


  /**
   * Returns a string representation of the option parameters.
   *
   * @return    the string representation
   */
  @Override
  String optionToString() {
    return hasTimeout ? String.valueOf (timeout) : "-";
  }

}



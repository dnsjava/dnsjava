package org.xbill.DNS;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * TCP Keepalive EDNS0 Option, as defined in https://tools.ietf.org/html/rfc7828
 *
 * @see OPTRecord
 * @author Klaus Malorny
 */
public class TcpKeepaliveOption extends EDNSOption {

  /** the timeout */
  private OptionalInt timeout;

  /** upper limit of the duration (exclusive) */
  private static final Duration UPPER_LIMIT = Duration.ofMillis(6553600);

  /** Constructor for an option with no timeout */
  public TcpKeepaliveOption() {
    super(EDNSOption.Code.TCP_KEEPALIVE);
    timeout = OptionalInt.empty();
  }

  /**
   * Constructor for an option with a given timeout.
   *
   * @param t the timeout time in 100ms units, may not be negative or larger than 65535
   */
  public TcpKeepaliveOption(int t) {
    super(EDNSOption.Code.TCP_KEEPALIVE);
    if (t < 0 || t > 65535)
      throw new IllegalArgumentException("timeout must be betwee 0 and 65535");
    timeout = OptionalInt.of(t);
  }

  /**
   * Constructor for an option with a given timeout. As the timeout has a coarser granularity than
   * the {@link Duration} class, values are rounded down.
   *
   * @param t the timeout time, must not be negative and must be lower than 6553.5 seconds
   */
  public TcpKeepaliveOption(Duration t) {
    super(EDNSOption.Code.TCP_KEEPALIVE);
    if (t.isNegative() || t.compareTo(UPPER_LIMIT) >= 0)
      throw new IllegalArgumentException(
          "timeout must be between 0 and 6553.6 seconds (exclusively)");
    timeout = OptionalInt.of((int) t.toMillis() / 100);
  }

  /**
   * Returns the timeout.
   *
   * @return the timeout in 100ms units
   */
  public OptionalInt getTimeout() {
    return timeout;
  }

  /**
   * Returns the timeout as a {@link Duration}.
   *
   * @return the timeout
   */
  public Optional<Duration> getTimeoutDuration() {
    return timeout.isPresent()
        ? Optional.of(Duration.ofMillis(timeout.getAsInt() * 100))
        : Optional.empty();
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
        timeout = OptionalInt.empty();
        break;
      case 2:
        timeout = OptionalInt.of(in.readU16());
        break;
      default:
        throw new WireParseException(
            "invalid length (" + length + ") of the data in the edns_tcp_keepalive option");
    }
  }

  /**
   * Converts an EDNS Option (the type-specific option data only) into wire format.
   *
   * @param out The output stream.
   */
  @Override
  void optionToWire(DNSOutput out) {
    if (timeout.isPresent()) out.writeU16(timeout.getAsInt());
  }

  /**
   * Returns a string representation of the option parameters.
   *
   * @return the string representation
   */
  @Override
  String optionToString() {
    return timeout.isPresent() ? String.valueOf(timeout.getAsInt()) : "-";
  }
}

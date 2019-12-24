package org.xbill.DNS;

import java.io.IOException;
import java.util.Optional;
import org.xbill.DNS.utils.base16;

/**
 * Cookie EDNS0 Option, as defined in https://tools.ietf.org/html/rfc7873
 *
 * @see OPTRecord
 * @author Klaus Malorny
 */
public class CookieOption extends EDNSOption {

  /** client cookie */
  private byte[] clientCookie;

  /** server cookie */
  private byte[] serverCookie;

  /** Default constructor for constructing instance from binary representation. */
  CookieOption() {
    super(EDNSOption.Code.COOKIE);
  }

  /**
   * Constructor.
   *
   * @param clientCookie the client cookie, which must consist of eight bytes
   */
  public CookieOption(byte[] clientCookie) {
    this(clientCookie, null);
  }

  /**
   * Constructor.
   *
   * @param clientCookie the client cookie, which must consist of eight bytes
   * @param serverCookie the server cookie, which must consist of 8 to 32 bytes if present
   */
  public CookieOption(byte[] clientCookie, byte[] serverCookie) {
    this();
    if (clientCookie == null) throw new IllegalArgumentException("client cookie must not be null");
    if (clientCookie.length != 8)
      throw new IllegalArgumentException("client cookie must consist of eight bytes");
    this.clientCookie = clientCookie;

    if (serverCookie != null) {
      int length = serverCookie.length;
      if (length < 8 || length > 32)
        throw new IllegalArgumentException("server cookie must consist of 8 to 32 bytes");
    }
    this.serverCookie = serverCookie;
  }

  /**
   * Returns the client cookie.
   *
   * @return the client cookie
   */
  public byte[] getClientCookie() {
    return clientCookie;
  }

  /**
   * Returns the server cookie.
   *
   * @return the server cookie
   */
  public Optional<byte[]> getServerCookie() {
    return Optional.ofNullable(serverCookie);
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
    if (length < 8) throw new WireParseException("invalid length of client cookie");
    clientCookie = in.readByteArray(8);
    if (length > 8) {
      if (length < 16 || length > 40)
        throw new WireParseException("invalid length of server cookie");
      serverCookie = in.readByteArray();
    }
  }

  /**
   * Converts an EDNS Option (the type-specific option data only) into wire format.
   *
   * @param out The output stream.
   */
  @Override
  void optionToWire(DNSOutput out) {
    out.writeByteArray(clientCookie);
    if (serverCookie != null) {
      out.writeByteArray(serverCookie);
    }
  }

  /**
   * Returns a string representation of the option parameters
   *
   * @return the string representation
   */
  @Override
  String optionToString() {
    return serverCookie != null
        ? base16.toString(clientCookie) + " " + base16.toString(serverCookie)
        : base16.toString(clientCookie);
  }
}

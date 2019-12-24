// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * The Client Subnet EDNS Option, defined in <a href="https://tools.ietf.org/html/rfc7871>Client
 * subnet in DNS requests</a>.
 *
 * <p>The option is used to convey information about the IP address of the originating client, so
 * that an authoritative server can make decisions based on this address, rather than the address of
 * the intermediate caching name server.
 *
 * <p>The option is transmitted as part of an OPTRecord in the additional section of a DNS message,
 * as defined by RFC 6891 (EDNS0).
 *
 * <p>The wire format of the option contains a 2-byte length field (1 for IPv4, 2 for IPv6), a
 * 1-byte source netmask, a 1-byte scope netmask, and an address truncated to the source netmask
 * length (where the final octet is padded with bits set to 0)
 *
 * @see OPTRecord
 * @author Brian Wellington
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 */
public class ClientSubnetOption extends EDNSOption {
  private int family;
  private int sourcePrefixLength;
  private int scopePrefixLength;
  private InetAddress address;

  ClientSubnetOption() {
    super(EDNSOption.Code.CLIENT_SUBNET);
  }

  private static int checkMaskLength(String field, int family, int val) {
    int max = Address.addressLength(family) * 8;
    if (val < 0 || val > max) {
      throw new IllegalArgumentException(
          "\"" + field + "\" " + val + " must be in the range [0.." + max + "]");
    }
    return val;
  }

  /**
   * Construct a Client Subnet option. Note that the number of significant bits in the address must
   * not be greater than the supplied source netmask. There may also be issues related to Java's
   * handling of mapped addresses
   *
   * @param sourcePrefixLength The length of the netmask pertaining to the query. In replies, it
   *     mirrors the same value as in the requests.
   * @param scopePrefixLength The length of the netmask pertaining to the reply. In requests, it
   *     MUST be set to 0. In responses, this may or may not match the source netmask.
   * @param address The address of the client.
   */
  public ClientSubnetOption(int sourcePrefixLength, int scopePrefixLength, InetAddress address) {
    super(EDNSOption.Code.CLIENT_SUBNET);

    this.family = Address.familyOf(address);
    this.sourcePrefixLength = checkMaskLength("source netmask", this.family, sourcePrefixLength);
    this.scopePrefixLength = checkMaskLength("scope netmask", this.family, scopePrefixLength);
    this.address = Address.truncate(address, sourcePrefixLength);

    if (!address.equals(this.address)) {
      throw new IllegalArgumentException("source netmask is not valid for address");
    }
  }

  /**
   * Construct a Client Subnet option with scope netmask set to 0.
   *
   * @param sourcePrefixLength The length of the netmask pertaining to the query. In replies, it
   *     mirrors the same value as in the requests.
   * @param address The address of the client.
   * @see ClientSubnetOption
   */
  public ClientSubnetOption(int sourcePrefixLength, InetAddress address) {
    this(sourcePrefixLength, 0, address);
  }

  /** Returns the family of the network address. This will be either IPv4 (1) or IPv6 (2). */
  public int getFamily() {
    return family;
  }

  /** Returns the source netmask. */
  public int getSourcePrefixLength() {
    return sourcePrefixLength;
  }

  /** Returns the scope netmask. */
  public int getScopePrefixLength() {
    return scopePrefixLength;
  }

  /** Returns the IP address of the client. */
  public InetAddress getAddress() {
    return address;
  }

  @Override
  void optionFromWire(DNSInput in) throws WireParseException {
    family = in.readU16();
    if (family != Address.IPv4 && family != Address.IPv6) {
      throw new WireParseException("unknown address family");
    }
    sourcePrefixLength = in.readU8();
    if (sourcePrefixLength > Address.addressLength(family) * 8) {
      throw new WireParseException("invalid source netmask");
    }
    scopePrefixLength = in.readU8();
    if (scopePrefixLength > Address.addressLength(family) * 8) {
      throw new WireParseException("invalid scope netmask");
    }

    // Read the truncated address
    byte[] addr = in.readByteArray();
    if (addr.length != (sourcePrefixLength + 7) / 8) {
      throw new WireParseException("invalid address");
    }

    // Convert it to a full length address.
    byte[] fulladdr = new byte[Address.addressLength(family)];
    System.arraycopy(addr, 0, fulladdr, 0, addr.length);

    try {
      address = InetAddress.getByAddress(fulladdr);
    } catch (UnknownHostException e) {
      throw new WireParseException("invalid address", e);
    }

    InetAddress tmp = Address.truncate(address, sourcePrefixLength);
    if (!tmp.equals(address)) {
      throw new WireParseException("invalid padding");
    }
  }

  @Override
  void optionToWire(DNSOutput out) {
    out.writeU16(family);
    out.writeU8(sourcePrefixLength);
    out.writeU8(scopePrefixLength);
    out.writeByteArray(address.getAddress(), 0, (sourcePrefixLength + 7) / 8);
  }

  @Override
  String optionToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(address.getHostAddress());
    sb.append("/");
    sb.append(sourcePrefixLength);
    sb.append(", scope netmask ");
    sb.append(scopePrefixLength);
    return sb.toString();
  }
}

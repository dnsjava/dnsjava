// Copyright (c) 2003-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A set of functions designed to deal with DNS names used in reverse mappings. For the IPv4 address
 * a.b.c.d, the reverse map name is d.c.b.a.in-addr.arpa. For an IPv6 address, the reverse map name
 * is ...ip6.arpa.
 *
 * @author Brian Wellington
 */
public final class ReverseMap {

  private static final Name inaddr4 = Name.fromConstantString("in-addr.arpa.");
  private static final Name inaddr6 = Name.fromConstantString("ip6.arpa.");

  /* Otherwise the class could be instantiated */
  private ReverseMap() {}

  /**
   * Creates a reverse map name corresponding to an address contained in an array of 4 bytes (for an
   * IPv4 address) or 16 bytes (for an IPv6 address).
   *
   * @param addr The address from which to build a name.
   * @return The name corresponding to the address in the reverse map.
   */
  public static Name fromAddress(byte[] addr) {
    if (addr.length != 4 && addr.length != 16) {
      throw new IllegalArgumentException("array must contain 4 or 16 elements");
    }

    StringBuilder sb = new StringBuilder();
    if (addr.length == 4) {
      for (int i = addr.length - 1; i >= 0; i--) {
        sb.append(addr[i] & 0xFF);
        if (i > 0) {
          sb.append(".");
        }
      }
    } else {
      int[] nibbles = new int[2];
      for (int i = addr.length - 1; i >= 0; i--) {
        nibbles[0] = (addr[i] & 0xFF) >> 4;
        nibbles[1] = addr[i] & 0xF;
        for (int j = nibbles.length - 1; j >= 0; j--) {
          sb.append(Integer.toHexString(nibbles[j]));
          if (i > 0 || j > 0) {
            sb.append(".");
          }
        }
      }
    }

    try {
      if (addr.length == 4) {
        return Name.fromString(sb.toString(), inaddr4);
      } else {
        return Name.fromString(sb.toString(), inaddr6);
      }
    } catch (TextParseException e) {
      throw new IllegalStateException("name cannot be invalid");
    }
  }

  /**
   * Creates a reverse map name corresponding to an address contained in an array of 4 integers
   * between 0 and 255 (for an IPv4 address) or 16 integers between 0 and 255 (for an IPv6 address).
   *
   * @param addr The address from which to build a name.
   * @return The name corresponding to the address in the reverse map.
   */
  public static Name fromAddress(int[] addr) {
    byte[] bytes = new byte[addr.length];
    for (int i = 0; i < addr.length; i++) {
      if (addr[i] < 0 || addr[i] > 0xFF) {
        throw new IllegalArgumentException("array must contain values between 0 and 255");
      }
      bytes[i] = (byte) addr[i];
    }
    return fromAddress(bytes);
  }

  /**
   * Creates a reverse map name corresponding to an address contained in an InetAddress.
   *
   * @param addr The address from which to build a name.
   * @return The name corresponding to the address in the reverse map.
   */
  public static Name fromAddress(InetAddress addr) {
    return fromAddress(addr.getAddress());
  }

  /**
   * Creates a reverse map name corresponding to an address contained in a String.
   *
   * @param addr The address from which to build a name.
   * @return The name corresponding to the address in the reverse map.
   * @throws UnknownHostException The string does not contain a valid address.
   */
  public static Name fromAddress(String addr, int family) throws UnknownHostException {
    byte[] array = Address.toByteArray(addr, family);
    if (array == null) {
      throw new UnknownHostException("Invalid IP address: " + addr);
    }
    return fromAddress(array);
  }

  /**
   * Creates a reverse map name corresponding to an address contained in a String.
   *
   * @param addr The address from which to build a name.
   * @return The name corresponding to the address in the reverse map.
   * @throws UnknownHostException The string does not contain a valid address.
   */
  public static Name fromAddress(String addr) throws UnknownHostException {
    byte[] array = Address.toByteArray(addr, Address.IPv4);
    if (array == null) {
      array = Address.toByteArray(addr, Address.IPv6);
    }
    if (array == null) {
      throw new UnknownHostException("Invalid IP address: " + addr);
    }
    return fromAddress(array);
  }

  /**
   * Parses the address from a reverse map string.
   *
   * @param name The string from which to build an address.
   * @return The address corresponding to the reverse map string.
   * @throws UnknownHostException the passed name is not a valid reverse map.
   * @since 3.1
   */
  public static InetAddress fromName(String name) throws UnknownHostException, TextParseException {
    return fromName(Name.fromString(name));
  }

  /**
   * Parses the address from a reverse map name.
   *
   * @param name The name from which to build an address.
   * @return The address corresponding to the reverse map name.
   * @throws UnknownHostException the passed name is not a valid reverse map.
   * @since 3.1
   */
  public static InetAddress fromName(Name name) throws UnknownHostException {
    if (name.labels() <= 3) {
      throw new UnknownHostException("Not an arpa address: " + name.toString());
    }

    byte[] ipBytes;
    if (name.subdomain(inaddr4)) {
      Name ip = name.relativize(inaddr4);
      if (ip.labels() > 4) {
        throw new UnknownHostException("Invalid IPv4 arpa address: " + name.toString());
      }

      ipBytes = new byte[4];
      try {
        for (int i = 0; i < ip.labels(); i++) {
          ipBytes[ip.labels() - i - 1] = (byte) Integer.parseInt(ip.getLabelString(i));
        }
      } catch (NumberFormatException e) {
        throw new UnknownHostException("Invalid IPv4 arpa address: " + name.toString());
      }
      return InetAddress.getByAddress(ipBytes);
    } else if (name.subdomain(inaddr6)) {
      Name ip = name.relativize(inaddr6);
      if (ip.labels() > 32) {
        throw new UnknownHostException("Invalid IPv6 arpa address: " + name.toString());
      }

      ipBytes = new byte[16];
      try {
        for (int i = 0; i < ip.labels(); i++) {
          ipBytes[(ip.labels() - i - 1) / 2] |=
              Byte.parseByte(ip.getLabelString(i), 16) << ((ip.labels() - i) % 2 == 0 ? 0 : 4);
        }
      } catch (NumberFormatException e) {
        throw new UnknownHostException("Invalid IPv6 arpa address: " + name.toString());
      }
    } else {
      throw new UnknownHostException("Not an arpa address: " + name.toString());
    }

    return InetAddress.getByAddress(ipBytes);
  }
}

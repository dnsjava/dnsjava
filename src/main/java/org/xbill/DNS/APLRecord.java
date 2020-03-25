// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.xbill.DNS.utils.base16;

/*
 * Note: this currently uses the same constants as the Address class;
 * this could change if more constants are defined for APL records.
 */

/**
 * APL - Address Prefix List.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc3123">RFC 3123: A DNS RR Type for Lists of Address
 *     Prefixes (APL RR)</a>
 */
public class APLRecord extends Record {

  public static class Element {
    public final int family;
    public final boolean negative;
    public final int prefixLength;
    public final Object address;

    private Element(int family, boolean negative, Object address, int prefixLength) {
      this.family = family;
      this.negative = negative;
      this.address = address;
      this.prefixLength = prefixLength;
      if (!validatePrefixLength(family, prefixLength)) {
        throw new IllegalArgumentException("invalid prefix length");
      }
    }

    /**
     * Creates an APL element corresponding to an IPv4 or IPv6 prefix.
     *
     * @param negative Indicates if this prefix is a negation.
     * @param address The IPv4 or IPv6 address.
     * @param prefixLength The length of this prefix, in bits.
     * @throws IllegalArgumentException The prefix length is invalid.
     */
    public Element(boolean negative, InetAddress address, int prefixLength) {
      this(Address.familyOf(address), negative, address, prefixLength);
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      if (negative) {
        sb.append("!");
      }
      sb.append(family);
      sb.append(":");
      if (family == Address.IPv4 || family == Address.IPv6) {
        sb.append(((InetAddress) address).getHostAddress());
      } else {
        sb.append(base16.toString((byte[]) address));
      }
      sb.append("/");
      sb.append(prefixLength);
      return sb.toString();
    }

    @Override
    public boolean equals(Object arg) {
      if (!(arg instanceof Element)) {
        return false;
      }
      Element elt = (Element) arg;
      return family == elt.family
          && negative == elt.negative
          && prefixLength == elt.prefixLength
          && address.equals(elt.address);
    }

    @Override
    public int hashCode() {
      return address.hashCode() + prefixLength + (negative ? 1 : 0);
    }
  }

  private List<Element> elements;

  APLRecord() {}

  private static boolean validatePrefixLength(int family, int prefixLength) {
    if (prefixLength < 0 || prefixLength >= 256) {
      return false;
    }
    return !((family == Address.IPv4 && prefixLength > 32)
        || (family == Address.IPv6 && prefixLength > 128));
  }

  /**
   * Creates an APL Record from the given data.
   *
   * @param elements The list of APL elements.
   */
  public APLRecord(Name name, int dclass, long ttl, List<Element> elements) {
    super(name, Type.APL, dclass, ttl);
    this.elements = new ArrayList<>(elements.size());
    for (Element element : elements) {
      if (element.family != Address.IPv4 && element.family != Address.IPv6) {
        throw new IllegalArgumentException("unknown family");
      }
      this.elements.add(element);
    }
  }

  private static byte[] parseAddress(byte[] in, int length) throws WireParseException {
    if (in.length > length) {
      throw new WireParseException("invalid address length");
    }
    if (in.length == length) {
      return in;
    }
    byte[] out = new byte[length];
    System.arraycopy(in, 0, out, 0, in.length);
    return out;
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    elements = new ArrayList<>(1);
    while (in.remaining() != 0) {
      int family = in.readU16();
      int prefix = in.readU8();
      int length = in.readU8();
      boolean negative = (length & 0x80) != 0;
      length &= ~0x80;

      byte[] data = in.readByteArray(length);
      Element element;
      if (!validatePrefixLength(family, prefix)) {
        throw new WireParseException("invalid prefix length");
      }

      if (family == Address.IPv4 || family == Address.IPv6) {
        data = parseAddress(data, Address.addressLength(family));
        InetAddress addr = InetAddress.getByAddress(data);
        element = new Element(negative, addr, prefix);
      } else {
        element = new Element(family, negative, data, prefix);
      }
      elements.add(element);
    }
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    elements = new ArrayList<>(1);
    while (true) {
      Tokenizer.Token t = st.get();
      if (!t.isString()) {
        break;
      }

      boolean negative = false;
      int family;
      int prefix;

      String s = t.value;
      int start = 0;
      if (s.startsWith("!")) {
        negative = true;
        start = 1;
      }
      int colon = s.indexOf(':', start);
      if (colon < 0) {
        throw st.exception("invalid address prefix element");
      }
      int slash = s.indexOf('/', colon);
      if (slash < 0) {
        throw st.exception("invalid address prefix element");
      }

      String familyString = s.substring(start, colon);
      String addressString = s.substring(colon + 1, slash);
      String prefixString = s.substring(slash + 1);

      try {
        family = Integer.parseInt(familyString);
      } catch (NumberFormatException e) {
        throw st.exception("invalid family");
      }
      if (family != Address.IPv4 && family != Address.IPv6) {
        throw st.exception("unknown family");
      }

      try {
        prefix = Integer.parseInt(prefixString);
      } catch (NumberFormatException e) {
        throw st.exception("invalid prefix length");
      }

      if (!validatePrefixLength(family, prefix)) {
        throw st.exception("invalid prefix length");
      }

      byte[] bytes = Address.toByteArray(addressString, family);
      if (bytes == null) {
        throw st.exception("invalid IP address " + addressString);
      }

      InetAddress address = InetAddress.getByAddress(bytes);
      elements.add(new Element(negative, address, prefix));
    }
    st.unget();
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    for (Iterator<Element> it = elements.iterator(); it.hasNext(); ) {
      Element element = it.next();
      sb.append(element);
      if (it.hasNext()) {
        sb.append(" ");
      }
    }
    return sb.toString();
  }

  /** Returns the list of APL elements. */
  public List<Element> getElements() {
    return elements;
  }

  private static int addressLength(byte[] addr) {
    for (int i = addr.length - 1; i >= 0; i--) {
      if (addr[i] != 0) {
        return i + 1;
      }
    }
    return 0;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    for (Element element : elements) {
      int length;
      byte[] data;
      if (element.family == Address.IPv4 || element.family == Address.IPv6) {
        InetAddress addr = (InetAddress) element.address;
        data = addr.getAddress();
        length = addressLength(data);
      } else {
        data = (byte[]) element.address;
        length = data.length;
      }
      int wlength = length;
      if (element.negative) {
        wlength |= 0x80;
      }
      out.writeU16(element.family);
      out.writeU8(element.prefixLength);
      out.writeU8(wlength);
      out.writeByteArray(data, 0, length);
    }
  }
}

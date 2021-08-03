// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * X25 - identifies the PSDN (Public Switched Data Network) address in the X.121 numbering plan
 * associated with a name.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1183">RFC 1183: New DNS RR Definitions</a>
 */
public class X25Record extends Record {
  private byte[] address;

  X25Record() {}

  private static byte[] checkAndConvertAddress(String address) {
    int length = address.length();
    byte[] out = new byte[length];
    for (int i = 0; i < length; i++) {
      char c = address.charAt(i);
      if (!Character.isDigit(c)) {
        return null;
      }
      out[i] = (byte) c;
    }
    return out;
  }

  /**
   * Creates an X25 Record from the given data
   *
   * @param address The X.25 PSDN address.
   * @throws IllegalArgumentException The address is not a valid PSDN address.
   */
  public X25Record(Name name, int dclass, long ttl, String address) {
    super(name, Type.X25, dclass, ttl);
    this.address = checkAndConvertAddress(address);
    if (this.address == null) {
      throw new IllegalArgumentException("invalid PSDN address " + address);
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    address = in.readCountedString();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    String addr = st.getString();
    this.address = checkAndConvertAddress(addr);
    if (this.address == null) {
      throw st.exception("invalid PSDN address " + addr);
    }
  }

  /** Returns the X.25 PSDN address. */
  public String getAddress() {
    return byteArrayToString(address, false);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeCountedString(address);
  }

  @Override
  protected String rrToString() {
    return byteArrayToString(address, true);
  }
}

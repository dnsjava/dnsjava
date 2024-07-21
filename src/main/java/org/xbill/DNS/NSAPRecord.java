// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.xbill.DNS.utils.base16;

/**
 * NSAP Address Record.
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc1706">RFC 1706: DNS NSAP Resource
 *     Records</a>
 */
public class NSAPRecord extends Record {
  private byte[] address;

  NSAPRecord() {}

  private static byte[] checkAndConvertAddress(String address) {
    if (!address.substring(0, 2).equalsIgnoreCase("0x")) {
      return null;
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    boolean partial = false;
    int current = 0;
    for (int i = 2; i < address.length(); i++) {
      char c = address.charAt(i);
      if (c == '.') {
        continue;
      }
      int value = Character.digit(c, 16);
      if (value == -1) {
        return null;
      }
      if (partial) {
        current += value;
        bytes.write(current);
        partial = false;
      } else {
        current = value << 4;
        partial = true;
      }
    }
    if (partial) {
      return null;
    }
    return bytes.toByteArray();
  }

  /**
   * Creates an NSAP Record from the given data
   *
   * @param address The NSAP address.
   * @throws IllegalArgumentException The address is not a valid NSAP address.
   */
  public NSAPRecord(Name name, int dclass, long ttl, String address) {
    super(name, Type.NSAP, dclass, ttl);
    this.address = checkAndConvertAddress(address);
    if (this.address == null) {
      throw new IllegalArgumentException("invalid NSAP address " + address);
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) {
    address = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    String addr = st.getString();
    this.address = checkAndConvertAddress(addr);
    if (this.address == null) {
      throw st.exception("invalid NSAP address " + addr);
    }
  }

  /** Returns the NSAP address. */
  public String getAddress() {
    return byteArrayToString(address, false);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeByteArray(address);
  }

  @Override
  protected String rrToString() {
    return "0x" + base16.toString(address);
  }
}

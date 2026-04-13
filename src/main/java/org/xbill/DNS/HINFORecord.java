// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Host Information - describes the CPU and OS of a host
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc1035">RFC 1035: Domain Names -
 *     Implementation and Specification</a>
 */
public class HINFORecord extends Record {
  private byte[] cpu;
  private byte[] os;

  HINFORecord() {}

  /**
   * Creates an HINFO Record from the given data
   *
   * @param cpu A string describing the host's CPU
   * @param os A string describing the host's OS
   * @throws IllegalArgumentException One of the strings has invalid escapes
   */
  public HINFORecord(Name name, int dclass, long ttl, String cpu, String os) {
    super(name, Type.HINFO, dclass, ttl);
    try {
      this.cpu = byteArrayFromString(cpu);
      this.os = byteArrayFromString(os);
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    cpu = in.readCountedString();
    os = in.readCountedString();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    try {
      cpu = byteArrayFromString(st.getString());
      os = byteArrayFromString(st.getString());
    } catch (TextParseException e) {
      throw st.exception(e.getMessage());
    }
  }

  /**
   * Returns the host's CPU as a string.
   *
   * @param escape if true, returns the RR textual representation of the underlying bytes. If false,
   *     returns just the simple string using the UTF-8 charset with no additional escaping.
   * @since 3.6.5
   */
  public String getCPU(boolean escape) {
    return escape ? byteArrayToString(cpu, false) : new String(cpu, StandardCharsets.UTF_8);
  }

  /** Returns the host's CPU as a string, escaped for RR textual representation */
  public String getCPU() {
    return getCPU(true);
  }

  /**
   * Returns the host's CPU as a raw byte-array
   *
   * @since 3.6.5
   */
  public byte[] getCPUAsByteArray() {
    return cpu;
  }

  /**
   * Returns the host's OS as a string.
   *
   * @param escape if true, returns the RR textual representation of the underlying bytes. If false,
   *     returns just the simple string using the UTF-8 charset with no additional escaping.
   * @since 3.6.5
   */
  public String getOS(boolean escape) {
    return escape ? byteArrayToString(os, false) : new String(os, StandardCharsets.UTF_8);
  }

  /** Returns the host's OS as a string, escaped for RR textual representation */
  public String getOS() {
    return getOS(true);
  }

  /**
   * Returns the host's OS as a raw byte-array
   *
   * @since 3.6.5
   */
  public byte[] getOSAsByteArray() {
    return os;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeCountedString(cpu);
    out.writeCountedString(os);
  }

  /** Converts to a string */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(byteArrayToString(cpu, true));
    sb.append(" ");
    sb.append(byteArrayToString(os, true));
    return sb.toString();
  }
}

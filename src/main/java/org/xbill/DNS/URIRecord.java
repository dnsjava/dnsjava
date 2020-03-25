// Implemented by Anthony Kirby (anthony@anthony.org)
// based on SRVRecord.java Copyright (c) 1999-2004 Brian Wellington

package org.xbill.DNS;

import java.io.IOException;

/**
 * Uniform Resource Identifier (URI) DNS Resource Record
 *
 * @author Anthony Kirby
 * @see <a href="https://tools.ietf.org/html/rfc7553">RFC 7553: The Uniform Resource Identifier
 *     (URI) DNS Resource Record</a>
 */
public class URIRecord extends Record {
  private int priority, weight;
  private byte[] target;

  URIRecord() {
    target = new byte[] {};
  }

  /**
   * Creates a URI Record from the given data
   *
   * @param priority The priority of this URI. Records with lower priority are preferred.
   * @param weight The weight, used to select between records at the same priority.
   * @param target The host/port running the service
   */
  public URIRecord(Name name, int dclass, long ttl, int priority, int weight, String target) {
    super(name, Type.URI, dclass, ttl);
    this.priority = checkU16("priority", priority);
    this.weight = checkU16("weight", weight);
    try {
      this.target = byteArrayFromString(target);
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    priority = in.readU16();
    weight = in.readU16();
    target = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    priority = st.getUInt16();
    weight = st.getUInt16();
    try {
      target = byteArrayFromString(st.getString());
    } catch (TextParseException e) {
      throw st.exception(e.getMessage());
    }
  }

  /** Converts rdata to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(priority).append(" ");
    sb.append(weight).append(" ");
    sb.append(byteArrayToString(target, true));
    return sb.toString();
  }

  /** Returns the priority */
  public int getPriority() {
    return priority;
  }

  /** Returns the weight */
  public int getWeight() {
    return weight;
  }

  /** Returns the target URI */
  public String getTarget() {
    return byteArrayToString(target, false);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(priority);
    out.writeU16(weight);
    out.writeByteArray(target);
  }
}

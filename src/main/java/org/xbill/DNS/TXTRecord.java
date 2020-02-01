// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.util.List;

/**
 * Text - stores text strings
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class TXTRecord extends TXTBase {
  TXTRecord() {}

  /**
   * Creates a TXT Record from the given data
   *
   * @param strings The text strings
   * @throws IllegalArgumentException One of the strings has invalid escapes
   */
  public TXTRecord(Name name, int dclass, long ttl, List<String> strings) {
    super(name, Type.TXT, dclass, ttl, strings);
  }

  /**
   * Creates a TXT Record from the given data
   *
   * @param string One text string
   * @throws IllegalArgumentException The string has invalid escapes
   */
  public TXTRecord(Name name, int dclass, long ttl, String string) {
    super(name, Type.TXT, dclass, ttl, string);
  }
}

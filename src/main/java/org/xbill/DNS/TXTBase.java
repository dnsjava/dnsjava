// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Implements common functionality for the many record types whose format is a list of strings.
 *
 * @author Brian Wellington
 */
abstract class TXTBase extends Record {
  protected List<byte[]> strings;

  protected TXTBase() {}

  protected TXTBase(Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected TXTBase(Name name, int type, int dclass, long ttl, List<String> strings) {
    super(name, type, dclass, ttl);
    if (strings == null) {
      throw new IllegalArgumentException("strings must not be null");
    }
    this.strings = new ArrayList<>(strings.size());
    Iterator<String> it = strings.iterator();
    try {
      while (it.hasNext()) {
        String s = it.next();
        this.strings.add(byteArrayFromString(s));
      }
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  protected TXTBase(Name name, int type, int dclass, long ttl, String string) {
    this(name, type, dclass, ttl, Collections.singletonList(string));
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    strings = new ArrayList<>(2);
    while (in.remaining() > 0) {
      byte[] b = in.readCountedString();
      strings.add(b);
    }
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    strings = new ArrayList<>(2);
    while (true) {
      Tokenizer.Token t = st.get();
      if (!t.isString()) {
        break;
      }
      try {
        strings.add(byteArrayFromString(t.value));
      } catch (TextParseException e) {
        throw st.exception(e.getMessage());
      }
    }
    st.unget();
  }

  /** converts to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    Iterator<byte[]> it = strings.iterator();
    while (it.hasNext()) {
      byte[] array = it.next();
      sb.append(byteArrayToString(array, true));
      if (it.hasNext()) {
        sb.append(" ");
      }
    }
    return sb.toString();
  }

  /**
   * Returns the text strings
   *
   * @return A list of Strings corresponding to the text strings.
   */
  public List<String> getStrings() {
    List<String> list = new ArrayList<>(strings.size());
    for (byte[] string : strings) {
      list.add(byteArrayToString(string, false));
    }
    return list;
  }

  /**
   * Returns the text strings
   *
   * @return A list of byte arrays corresponding to the text strings.
   */
  public List<byte[]> getStringsAsByteArrays() {
    return strings;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    for (byte[] b : strings) {
      out.writeCountedString(b);
    }
  }
}

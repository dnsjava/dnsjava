// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004-2009 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.io.Serializable;
import java.util.Iterator;
import java.util.TreeSet;

/**
 * Routines for deal with the lists of types found in NSEC/NSEC3 records.
 *
 * @author Brian Wellington
 */
final class TypeBitmap implements Serializable {

  private static final long serialVersionUID = -125354057735389003L;

  private final TreeSet<Integer> types;

  private TypeBitmap() {
    types = new TreeSet<>();
  }

  public TypeBitmap(int[] array) {
    this();
    for (int value : array) {
      Type.check(value);
      types.add(value);
    }
  }

  public TypeBitmap(DNSInput in) throws WireParseException {
    this();

    // Encoding: ( Window Block # | Bitmap Length | Bitmap )+
    int lastWindowBlockNumber = -1;
    while (in.remaining() > 0) {
      // Validate block size, which is at least 2 bytes: block number + map length
      if (in.remaining() < 2) {
        throw new WireParseException("invalid bitmap descriptor");
      }

      int windowBlockNumber = getWindowBlockNumber(in, lastWindowBlockNumber);
      int mapLength = getMapLength(in);
      for (int i = 0; i < mapLength; i++) {
        // Test each bit (of the non-zero bytes) in the bitmap for 1. If set, this is an enabled
        // type.
        int bitmapByte = in.readU8();
        for (int j = 0; j < 8 && bitmapByte > 0; j++) {
          if ((bitmapByte & (1 << (7 - j))) != 0) {
            types.add(windowBlockNumber * 256 + i * 8 + j);
          }
        }
      }
    }
  }

  private static int getWindowBlockNumber(DNSInput in, int lastWindowBlockNumber)
      throws WireParseException {
    int windowBlockNumber = in.readU8();
    if (windowBlockNumber < lastWindowBlockNumber) {
      throw new WireParseException("invalid ordering");
    }
    return windowBlockNumber;
  }

  private static int getMapLength(DNSInput in) throws WireParseException {
    int mapLength = in.readU8();
    if (mapLength > in.remaining()) {
      throw new WireParseException("invalid bitmap");
    }
    return mapLength;
  }

  public TypeBitmap(Tokenizer st) throws IOException {
    this();
    while (true) {
      Tokenizer.Token t = st.get();
      if (!t.isString()) {
        break;
      }
      int typecode = Type.value(t.value());
      if (typecode < 0) {
        throw st.exception("Invalid type: " + t.value());
      }
      types.add(typecode);
    }
    st.unget();
  }

  public int[] toArray() {
    int[] array = new int[types.size()];
    int n = 0;
    for (Integer type : types) {
      array[n++] = type;
    }
    return array;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    for (Iterator<Integer> it = types.iterator(); it.hasNext(); ) {
      int t = it.next();
      sb.append(Type.string(t));
      if (it.hasNext()) {
        sb.append(' ');
      }
    }
    return sb.toString();
  }

  private static void mapToWire(DNSOutput out, TreeSet<Integer> map, int mapbase) {
    int arraymax = map.last() & 0xFF;
    int arraylength = (arraymax / 8) + 1;
    int[] array = new int[arraylength];
    out.writeU8(mapbase);
    out.writeU8(arraylength);
    for (int typecode : map) {
      array[(typecode & 0xFF) / 8] |= 1 << (7 - typecode % 8);
    }
    for (int j = 0; j < arraylength; j++) {
      out.writeU8(array[j]);
    }
  }

  public void toWire(DNSOutput out) {
    if (types.isEmpty()) {
      return;
    }

    int mapbase = -1;
    TreeSet<Integer> map = new TreeSet<>();

    for (Integer type : types) {
      int t = type;
      int base = t >> 8;
      if (base != mapbase) {
        if (!map.isEmpty()) {
          mapToWire(out, map, mapbase);
          map.clear();
        }
        mapbase = base;
      }
      map.add(t);
    }
    mapToWire(out, map, mapbase);
  }

  public boolean empty() {
    return types.isEmpty();
  }

  public boolean contains(int typecode) {
    return types.contains(typecode);
  }
}

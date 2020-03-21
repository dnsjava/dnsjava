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

  private TreeSet<Integer> types;

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
    int lastbase = -1;
    while (in.remaining() > 0) {
      if (in.remaining() < 2) {
        throw new WireParseException("invalid bitmap descriptor");
      }
      int mapbase = in.readU8();
      if (mapbase < lastbase) {
        throw new WireParseException("invalid ordering");
      }
      int maplength = in.readU8();
      if (maplength > in.remaining()) {
        throw new WireParseException("invalid bitmap");
      }
      for (int i = 0; i < maplength; i++) {
        int current = in.readU8();
        if (current == 0) {
          continue;
        }
        for (int j = 0; j < 8; j++) {
          if ((current & (1 << (7 - j))) == 0) {
            continue;
          }
          int typecode = mapbase * 256 + +i * 8 + j;
          types.add(typecode);
        }
      }
    }
  }

  public TypeBitmap(Tokenizer st) throws IOException {
    this();
    while (true) {
      Tokenizer.Token t = st.get();
      if (!t.isString()) {
        break;
      }
      int typecode = Type.value(t.value);
      if (typecode < 0) {
        throw st.exception("Invalid type: " + t.value);
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
    for (Integer integer : map) {
      int typecode = integer;
      array[(typecode & 0xFF) / 8] |= 1 << (7 - typecode % 8);
    }
    for (int j = 0; j < arraylength; j++) {
      out.writeU8(array[j]);
    }
  }

  public void toWire(DNSOutput out) {
    if (types.size() == 0) {
      return;
    }

    int mapbase = -1;
    TreeSet<Integer> map = new TreeSet<>();

    for (Integer type : types) {
      int t = type;
      int base = t >> 8;
      if (base != mapbase) {
        if (map.size() > 0) {
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

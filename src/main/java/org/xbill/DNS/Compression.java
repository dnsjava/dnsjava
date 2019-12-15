// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import lombok.extern.slf4j.Slf4j;

/**
 * DNS Name Compression object.
 *
 * @see Message
 * @see Name
 * @author Brian Wellington
 */
@Slf4j
public class Compression {

  private static class Entry {
    Name name;
    int pos;
    Entry next;
  }

  private static final int TABLE_SIZE = 17;
  private static final int MAX_POINTER = 0x3FFF;
  private Entry[] table;

  /** Creates a new Compression object. */
  public Compression() {
    table = new Entry[TABLE_SIZE];
  }

  /**
   * Adds a compression entry mapping a name to a position in a message.
   *
   * @param pos The position at which the name is added.
   * @param name The name being added to the message.
   */
  public void add(int pos, Name name) {
    if (pos > MAX_POINTER) {
      return;
    }
    int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
    Entry entry = new Entry();
    entry.name = name;
    entry.pos = pos;
    entry.next = table[row];
    table[row] = entry;
    log.trace("Adding {} at {}", name, pos);
  }

  /**
   * Retrieves the position of the given name, if it has been previously included in the message.
   *
   * @param name The name to find in the compression table.
   * @return The position of the name, or -1 if not found.
   */
  public int get(Name name) {
    int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
    int pos = -1;
    for (Entry entry = table[row]; entry != null; entry = entry.next) {
      if (entry.name.equals(name)) {
        pos = entry.pos;
      }
    }
    log.trace("Looking for {}, found {}", name, pos);
    return pos;
  }
}

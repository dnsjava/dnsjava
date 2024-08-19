// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;
import lombok.Getter;

/**
 * A DNS zone. This encapsulates all data related to a zone, and provides convenient lookup methods.
 * A zone always contains a {@link SOARecord} and at least one {@link NSRecord}.
 *
 * @implNote This class uses a {@link java.util.concurrent.locks.ReadWriteLock} to ensure access and
 *     manipulation is safe from multiple threads. Iterators are "weakly consistent" (see the
 *     package info from {@code java.util.concurrent}).
 * @author Brian Wellington
 */
public class Zone implements Serializable, Iterable<RRset> {
  /** A primary zone. */
  public static final int PRIMARY = 1;

  /** A secondary zone. */
  public static final int SECONDARY = 2;

  private final transient ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();
  private final transient ReentrantReadWriteLock.ReadLock readLock = readWriteLock.readLock();
  private final transient ReentrantReadWriteLock.WriteLock writeLock = readWriteLock.writeLock();

  private final Map<Name, Object> data = new ConcurrentSkipListMap<>();

  private Object originNode;
  private boolean hasWild;

  /** Returns the zone's origin. */
  @Getter private Name origin;

  /** Returns the zone origin's {@link NSRecord NS records}. */
  private RRset NS;

  /** Returns the zone's {@link SOARecord SOA record}. */
  @Getter private SOARecord SOA;

  /** Returns the zone's {@link DClass class}. */
  public int getDClass() {
    return DClass.IN;
  }

  /** Returns the zone origin's {@link NSRecord NS records}. */
  public RRset getNS() {
    return withReadLock(() -> new RRset(NS));
  }

  // ------------- Constructors

  /**
   * Creates a zone from the records in the specified master file.
   *
   * @param zone The name of the zone.
   * @param file The master file to read from.
   * @throws IllegalArgumentException if {@code zone} or {@code file} is {@code null}.
   * @throws IOException if the zone file does not contain a {@link SOARecord} or no {@link
   *     NSRecord}s.
   * @see Master
   */
  public Zone(Name zone, String file) throws IOException {
    if (zone == null) {
      throw new IllegalArgumentException("no zone name specified");
    }

    if (file == null) {
      throw new IllegalArgumentException("no file name specified");
    }

    try (Master m = new Master(file, zone)) {
      Record record;

      origin = zone;
      while ((record = m.nextRecord()) != null) {
        maybeAddRecord(record);
      }
    }
    validate();
  }

  /**
   * Creates a zone from an array of records.
   *
   * @param zone The name of the zone.
   * @param records The records to add to the zone.
   * @throws IllegalArgumentException if {@code zone} or {@code records} is {@code null}.
   * @throws IOException if the records do not contain a {@link SOARecord} or no {@link NSRecord}s.
   * @see Master
   */
  public Zone(Name zone, Record... records) throws IOException {
    if (zone == null) {
      throw new IllegalArgumentException("no zone name specified");
    }
    if (records == null) {
      throw new IllegalArgumentException("no records are specified");
    }
    origin = zone;
    for (Record record : records) {
      maybeAddRecord(record);
    }
    validate();
  }

  /**
   * Creates a zone by doing the specified zone transfer.
   *
   * @param xfrin The incoming zone transfer to execute.
   * @throws IllegalArgumentException if {@code xfrin} is {@code null}.
   * @throws IOException if the zone does not contain a {@link SOARecord} or no {@link NSRecord}s.
   * @see ZoneTransferIn
   */
  public Zone(ZoneTransferIn xfrin) throws IOException, ZoneTransferException {
    if (xfrin == null) {
      throw new IllegalArgumentException("no xfrin specified");
    }

    fromXFR(xfrin);
  }

  /**
   * Creates a zone by performing a zone transfer from the specified host. This uses the default
   * port and no {@link TSIG}. Use {@link Zone#Zone(ZoneTransferIn)} for more control.
   *
   * @param zone The zone to transfer.
   * @param dclass The {@link DClass} of the zone to transfer.
   * @param remote The remote host to transfer from.
   * @throws IllegalArgumentException if {@code zone} or {@code remote} is {@code null}.
   * @throws IOException if the zone does not contain a {@link SOARecord} or no {@link NSRecord}s.
   * @throws InvalidDClassException if {@code dclass} is not a valid {@link DClass}.
   * @see ZoneTransferIn
   */
  public Zone(Name zone, int dclass, String remote) throws IOException, ZoneTransferException {
    if (zone == null) {
      throw new IllegalArgumentException("no zone name specified");
    }
    DClass.check(dclass);

    ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(zone, remote, null);
    xfrin.setDClass(dclass);
    fromXFR(xfrin);
  }

  private void fromXFR(ZoneTransferIn xfrin) throws IOException, ZoneTransferException {
    origin = xfrin.getName();
    xfrin.run();
    if (!xfrin.isAXFR()) {
      throw new IllegalArgumentException("zones can only be created from AXFRs");
    }

    for (Record record : xfrin.getAXFR()) {
      maybeAddRecord(record);
    }
    validate();
  }

  private void maybeAddRecord(Record record) throws IOException {
    int rtype = record.getType();
    Name name = record.getName();

    if (rtype == Type.SOA && !name.equals(origin)) {
      throw new IOException("SOA owner " + name + " does not match zone origin " + origin);
    }

    if (name.subdomain(origin)) {
      addRecord(record);
    }
  }

  private void validate() throws IOException {
    originNode = exactName(origin);
    if (originNode == null) {
      throw new IOException(origin + ": no data specified");
    }

    RRset rrset = oneRRsetWithoutLock(originNode, Type.SOA);
    if (rrset == null || rrset.size() != 1) {
      throw new IOException(origin + ": exactly 1 SOA must be specified");
    }
    SOA = (SOARecord) rrset.first();

    NS = oneRRsetWithoutLock(originNode, Type.NS);
    if (NS == null) {
      throw new IOException(origin + ": no NS set specified");
    }
  }

  // ------------- Iterators

  /** Returns an iterator over the {@link RRset RRsets} in the zone. */
  @Override
  public Iterator<RRset> iterator() {
    return new ZoneIterator(false);
  }

  /**
   * Returns an Iterator over the {@link RRset RRsets} in the zone that can be used to construct an
   * AXFR response. This is identical to {@link #iterator} except that the SOA is returned at the
   * end as well as the beginning.
   */
  public Iterator<RRset> AXFR() {
    return new ZoneIterator(true);
  }

  // ------------- Manipulation

  /**
   * Adds a record to the zone. If there is an existing {@link RRset} of the same {@link Name} and
   * {@link Type}, the record is <b>added</b> to this set.
   *
   * @param r The record to add.
   * @throws IllegalArgumentException if {@code name} is {@code null} or if the rrset name does not
   *     match the zone origin.
   */
  public <T extends Record> void addRecord(T r) {
    if (r == null) {
      throw new IllegalArgumentException("r must not be null");
    }

    Name name = r.getName();
    int rtype = r.getRRsetType();
    int actualType = r.getType();

    if (rtype == Type.SOA && !name.equals(origin)) {
      throw new IllegalArgumentException(
          "SOA owner " + name + " does not match zone origin " + origin);
    }

    if (!name.subdomain(origin)) {
      throw new IllegalArgumentException(
          "name " + name + " is absolute and not a subdomain of " + origin);
    }

    withWriteLock(
        () -> {
          RRset rrset = findRRsetWithoutLock(name, rtype);
          if (rrset == null) {
            rrset = new RRset(r);
            addRRsetWithoutLock(name, rrset);
          } else {
            // Adding a SOA must replace any existing record. We validated before that the zone name
            // didn't change
            if (actualType == Type.SOA) {
              rrset.deleteRR(SOA);
              SOA = (SOARecord) r;
            }

            rrset.addRR(r);
          }
        });
  }

  /**
   * Removes a record from the zone.
   *
   * @param r The record to remove.
   * @throws IllegalArgumentException if {@code r} is {@code null}, if the record to remove is the
   *     {@link SOARecord} or the last {@link NSRecord}.
   */
  public void removeRecord(Record r) {
    if (r == null) {
      throw new IllegalArgumentException("r must not be null");
    }

    Name name = r.getName();
    int rtype = r.getRRsetType();

    if (r.getType() == Type.SOA) {
      throw new IllegalArgumentException("Cannot remove SOA record");
    }

    withWriteLock(
        () -> {
          RRset rrset = findRRsetWithoutLock(name, rtype);
          if (rrset == null) {
            // No set found, thus no record to remove
            return;
          }

          if (rtype == Type.NS && rrset.size() == 1) {
            throw new IllegalArgumentException("Cannot remove all NS");
          }

          if (rrset.size() + rrset.sigSize() > 1) {
            rrset.deleteRR(r);
          } else {
            // Remove the set (and maybe the entire name) if the set is now empty
            removeRRsetWithoutLock(name, rtype);
          }
        });
  }

  /**
   * Adds an RRset to the zone.
   *
   * @implNote An existing {@link RRset} of the same {@link Name} and {@link Type} is
   *     <b>replaced</b>.
   * @param rrset The RRset to add.
   * @see RRset
   * @throws IllegalArgumentException if {@code rrset} is {@code null} or if the rrset name is not a
   *     {@link Name#subdomain(Name) subdomain} of the zone origin (or, in case of a SOA, is not
   *     equal to the zone origin).
   */
  public void addRRset(RRset rrset) {
    if (rrset == null) {
      throw new IllegalArgumentException("rrset must not be null");
    }

    Name name = rrset.getName();
    int type = rrset.getType();
    if (type == Type.SOA) {
      if (!name.equals(origin)) {
        throw new IllegalArgumentException(
            "SOA owner " + name + " does not match zone origin " + origin);
      }

      if (rrset.size() != 1) {
        throw new IllegalArgumentException(origin + ": exactly 1 SOA must be specified");
      }
    }

    if (!name.subdomain(origin)) {
      throw new IllegalArgumentException(
          "name " + name + " is absolute and not a subdomain of " + origin);
    }

    withWriteLock(
        () -> {
          addRRsetWithoutLock(name, rrset);
          if (type == Type.SOA) {
            SOA = (SOARecord) rrset.first();
          }
        });
  }

  /**
   * Removes an RRset from the zone.
   *
   * @param name The name to remove.
   * @param type The type to remove.
   * @throws IllegalArgumentException if {@code name} is {@code null}.
   * @throws InvalidTypeException if the specified {@code type} is invalid or {@link Type#SOA} or
   *     {@link Type#NS}.
   * @see RRset
   * @since 3.6
   */
  public void removeRRset(Name name, int type) {
    if (name == null) {
      throw new IllegalArgumentException("name must not be null");
    }
    Type.check(type);

    withWriteLock(() -> removeRRsetWithoutLock(name, type));
  }

  // ------------- Search

  /**
   * Looks up Records in the zone, finding exact matches only.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return The matching RRset or {@code null} if no exact match is found.
   * @throws IllegalArgumentException if {@code name} is {@code null}.
   * @throws InvalidTypeException if the specified {@code type} is invalid.
   * @see RRset
   */
  public RRset findExactMatch(Name name, int type) {
    if (name == null) {
      throw new IllegalArgumentException("name must not be null");
    }
    Type.check(type);
    return withReadLock(
        () -> {
          RRset set = findRRsetWithoutLock(name, type);
          if (set == null) {
            return null;
          }

          // Create a copy to keep the thread safety guarantees and consistency
          return new RRset(set);
        });
  }

  /**
   * Looks up Records in the zone. The answer can be a {@code CNAME} instead of the actual requested
   * type and wildcards are expanded.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return A SetResponse object
   * @throws IllegalArgumentException if {@code name} is {@code null}.
   * @throws InvalidTypeException if the specified {@code type} is invalid.
   * @see SetResponse
   */
  public SetResponse findRecords(Name name, int type) {
    if (name == null) {
      throw new IllegalArgumentException("name must not be null");
    }
    Type.check(type);

    if (!name.subdomain(origin)) {
      return SetResponse.ofType(SetResponseType.NXDOMAIN);
    }

    return withReadLock(() -> findRecordsWithoutLock(name, type));
  }

  // ----------- Internal
  private <T> T withReadLock(Supplier<T> callable) {
    readLock.lock();
    try {
      return callable.get();
    } finally {
      readLock.unlock();
    }
  }

  private void withWriteLock(Runnable callable) {
    writeLock.lock();
    try {
      callable.run();
    } finally {
      writeLock.unlock();
    }
  }

  private Object exactName(Name name) {
    return data.get(name);
  }

  @SuppressWarnings("unchecked")
  private List<RRset> allRRsetsWithoutLock(Object types) {
    if (types instanceof List) {
      return (List<RRset>) types;
    } else {
      return Collections.singletonList((RRset) types);
    }
  }

  private RRset oneRRsetWithoutLock(Object types, int type) {
    if (type == Type.ANY) {
      throw new IllegalArgumentException("Cannot lookup an exact match for type ANY");
    }

    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<RRset> list = (List<RRset>) types;
      for (RRset set : list) {
        if (set.getType() == type) {
          return set;
        }
      }
    } else {
      RRset set = (RRset) types;
      if (set.getType() == type) {
        return set;
      }
    }

    return null;
  }

  private RRset findRRsetWithoutLock(Name name, int type) {
    Object types = exactName(name);
    if (types == null) {
      return null;
    }
    return oneRRsetWithoutLock(types, type);
  }

  private void addRRsetWithoutLock(Name name, RRset rrset) {
    if (!hasWild && name.isWild()) {
      hasWild = true;
    }

    Object types = data.get(name);

    // Nothing in the zone for this name, add the set directly
    if (types == null) {
      data.put(name, rrset);
      return;
    }

    int rtype = rrset.getType();

    // Multiple types for this name
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<RRset> list = (List<RRset>) types;
      for (int i = 0; i < list.size(); i++) {
        RRset set = list.get(i);
        // There's already a set of the specified type, replace it
        if (set.getType() == rtype) {
          list.set(i, rrset);
          return;
        }
      }

      // The new type doesn't exist yet, add it
      list.add(rrset);
    } else {
      // One type for this name
      RRset set = (RRset) types;
      if (set.getType() == rtype) {
        // There's already a set of the specified type, replace it
        data.put(name, rrset);
      } else {
        // Different type, replace the RRset in the map with a list
        LinkedList<RRset> list = new LinkedList<>();
        list.add(set);
        list.add(rrset);
        data.put(name, list);
      }
    }
  }

  private void removeRRsetWithoutLock(Name name, int type) {
    if (type == Type.SOA) {
      throw new IllegalArgumentException("Cannot remove SOA");
    }

    if (type == Type.NS) {
      throw new IllegalArgumentException("Cannot remove all NS");
    }

    Object types = data.get(name);
    // Nothing in the zone for this name/type
    if (types == null) {
      return;
    }

    // Multiple types for this name
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<RRset> list = (List<RRset>) types;
      for (int i = 0; i < list.size(); i++) {
        RRset set = list.get(i);
        if (set.getType() == type) {
          // The type of this RRset matched, remove the set
          list.remove(i);
          break;
        }
      }

      // No types left, remove the entire name
      if (list.isEmpty()) {
        data.remove(name);
      }
    } else {
      // One type for this name
      RRset set = (RRset) types;
      if (set.getType() != type) {
        // Type doesn't match, nothing to remove
        return;
      }

      // The only type matched, remove the entire name
      data.remove(name);
    }
  }

  private SetResponse findRecordsWithoutLock(Name name, int type) {
    int labels = name.labels();
    int olabels = origin.labels();

    for (int tlabels = olabels; tlabels <= labels; tlabels++) {
      boolean isOrigin = tlabels == olabels;
      boolean isExact = tlabels == labels;

      Name tname;
      if (isOrigin) {
        tname = origin;
      } else if (isExact) {
        tname = name;
      } else {
        tname = new Name(name, labels - tlabels);
      }

      Object types = exactName(tname);
      if (types == null) {
        continue;
      }

      // If this is a delegation, return that.
      if (!isOrigin) {
        RRset ns = oneRRsetWithoutLock(types, Type.NS);
        if (ns != null) {
          return SetResponse.ofType(SetResponseType.DELEGATION, ns);
        }
      }

      // If this is an ANY lookup, return everything.
      if (isExact && type == Type.ANY) {
        SetResponse sr = SetResponse.ofType(SetResponseType.SUCCESSFUL);
        for (RRset set : allRRsetsWithoutLock(types)) {
          sr.addRRset(set);
        }
        return sr;
      }

      // If this is the name, look for the actual type or a CNAME.
      // Otherwise, look for a DNAME.
      if (isExact) {
        RRset rrset = oneRRsetWithoutLock(types, type);
        if (rrset != null) {
          return SetResponse.ofType(SetResponseType.SUCCESSFUL, rrset);
        }
        rrset = oneRRsetWithoutLock(types, Type.CNAME);
        if (rrset != null) {
          return SetResponse.ofType(SetResponseType.CNAME, rrset);
        }
      } else {
        RRset rrset = oneRRsetWithoutLock(types, Type.DNAME);
        if (rrset != null) {
          return SetResponse.ofType(SetResponseType.DNAME, rrset);
        }
      }

      // We found the name, but not the type.
      if (isExact) {
        return SetResponse.ofType(SetResponseType.NXRRSET);
      }
    }

    if (hasWild) {
      for (int i = 0; i < labels - olabels; i++) {
        Name tname = name.wild(i + 1);
        Object types = exactName(tname);
        if (types == null) {
          continue;
        }

        if (type == Type.ANY) {
          SetResponse sr = SetResponse.ofType(SetResponseType.SUCCESSFUL);
          for (RRset set : allRRsetsWithoutLock(types)) {
            sr.addRRset(expandSet(set, name));
          }
          return sr;
        } else {
          RRset rrset = oneRRsetWithoutLock(types, type);
          if (rrset != null) {
            return SetResponse.ofType(SetResponseType.SUCCESSFUL, expandSet(rrset, name));
          }
        }
      }
    }

    return SetResponse.ofType(SetResponseType.NXDOMAIN);
  }

  private RRset expandSet(RRset set, Name tname) {
    RRset expandedSet = new RRset();
    for (Record r : set.rrs(false)) {
      expandedSet.addRR(r.withName(tname));
    }
    for (RRSIGRecord r : set.sigs()) {
      expandedSet.addRR(r.withName(tname));
    }
    return expandedSet;
  }

  private void nodeToString(StringBuilder sb, Object node) {
    List<RRset> sets = allRRsetsWithoutLock(node);
    for (RRset rrset : sets) {
      rrset.rrs(false).forEach(r -> sb.append(r).append('\n'));
      rrset.sigs().forEach(r -> sb.append(r).append('\n'));
    }
  }

  /**
   * Returns the contents of the zone in master file format.
   *
   * @see Master
   */
  public String toMasterFile() {
    StringBuilder sb = new StringBuilder();
    withReadLock(
        () -> {
          nodeToString(sb, originNode);
          for (Map.Entry<Name, Object> entry : data.entrySet()) {
            if (!origin.equals(entry.getKey())) {
              nodeToString(sb, entry.getValue());
            }
          }
          return null;
        });
    return sb.toString();
  }

  /**
   * Returns the contents of the zone as a string.
   *
   * @see #toMasterFile
   */
  @Override
  public String toString() {
    return toMasterFile();
  }

  class ZoneIterator implements Iterator<RRset> {
    private final Iterator<Map.Entry<Name, Object>> zoneEntries;
    private List<RRset> current;
    private int index;
    private boolean wantLastSOA;
    private RRset returnedSet;
    private RRset soaSet;

    ZoneIterator(boolean axfr) {
      zoneEntries = data.entrySet().iterator();
      wantLastSOA = axfr;

      // Start the iterator at origin, with SOA and NS as the first and second entries
      // Create a copy of the RRset list to ensure that concurrent manipulation is safe
      List<RRset> originSets =
          withReadLock(() -> new ArrayList<>(allRRsetsWithoutLock(originNode)));
      RRset[] sortedOriginSets = new RRset[originSets.size()];
      current = Arrays.asList(sortedOriginSets);
      for (int i = 0, j = 2; i < originSets.size(); i++) {
        RRset originSet = originSets.get(i);
        int type = originSet.getType();
        if (type == Type.SOA) {
          sortedOriginSets[0] = soaSet = new RRset(originSet);
        } else if (type == Type.NS) {
          sortedOriginSets[1] = new RRset(originSet);
        } else {
          sortedOriginSets[j++] = new RRset(originSet);
        }
      }
    }

    @Override
    public boolean hasNext() {
      return current != null || wantLastSOA;
    }

    @Override
    public RRset next() {
      if (!hasNext()) {
        throw new NoSuchElementException("No more elements");
      }

      // If AXFR was requested, return the SOA as the last set again
      if (current == null) {
        wantLastSOA = false;
        returnedSet = soaSet;
        return returnedSet;
      }

      // Create a copy of the RRset to prevent manipulation of the zone via the returned set
      returnedSet = new RRset(current.get(index++));

      // Move to the next iterator step if there are no more sets at the current name
      if (index == current.size()) {
        current = null;
        while (zoneEntries.hasNext()) {
          Map.Entry<Name, Object> entry = zoneEntries.next();

          // Skip origin, the iterator started with it
          if (entry.getKey().equals(origin)) {
            continue;
          }

          // Create a copy of the RRset list to ensure that concurrent manipulation is safe
          List<RRset> sets =
              withReadLock(() -> new ArrayList<>(allRRsetsWithoutLock(entry.getValue())));
          if (sets.isEmpty()) {
            // Ignore empty sets (they shouldn't exist anyway)
            continue;
          }

          current = sets;
          index = 0;
          break;
        }
      }

      return returnedSet;
    }

    /**
     * Removes the current {@link RRset} from the zone.
     *
     * @throws IllegalArgumentException when there are no more elements; on attempting to remove the
     *     SOA; when attempting to remove the NS set.
     * @since 3.6
     */
    @Override
    public void remove() {
      if (returnedSet == null) {
        throw new IllegalStateException("Not at an element");
      }

      withWriteLock(() -> removeRRsetWithoutLock(returnedSet.getName(), returnedSet.getType()));
    }
  }
}

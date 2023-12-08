// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.io.Serializable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A DNS Zone. This encapsulates all data related to a Zone, and provides convenient lookup methods.
 *
 * @author Brian Wellington
 */
public class Zone implements Serializable {

  private transient ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();
  private transient ReentrantReadWriteLock.ReadLock readLock = readWriteLock.readLock();
  private transient ReentrantReadWriteLock.WriteLock writeLock = readWriteLock.writeLock();

  /** A primary zone */
  public static final int PRIMARY = 1;

  /** A secondary zone */
  public static final int SECONDARY = 2;

  private Map<Name, Object> data;
  private Name origin;
  private Object originNode;
  private RRset NS;
  private SOARecord SOA;
  private boolean hasWild;

  class ZoneIterator implements Iterator<RRset> {
    private final Iterator<Map.Entry<Name, Object>> zentries;
    private RRset[] current;
    private int count;
    private boolean wantLastSOA;

    ZoneIterator(boolean axfr) throws IllegalMonitorStateException {
      readLock.lock();
      zentries = data.entrySet().iterator();
      wantLastSOA = axfr;
      RRset[] sets = allRRsets(originNode);
      current = new RRset[sets.length];
      for (int i = 0, j = 2; i < sets.length; i++) {
        int type = sets[i].getType();
        if (type == Type.SOA) {
          current[0] = sets[i];
        } else if (type == Type.NS) {
          current[1] = sets[i];
        } else {
          current[j++] = sets[i];
        }
      }
      readLock.unlock();
    }

    @Override
    public boolean hasNext() {
      return current != null || wantLastSOA;
    }

    @Override
    public RRset next() throws IllegalMonitorStateException {
      if (!hasNext()) {
        throw new NoSuchElementException();
      }
      if (current == null) {
        wantLastSOA = false;
        return oneRRset(originNode, Type.SOA);
      }
      RRset set = current[count++];
      if (count == current.length) {
        current = null;
        while (zentries.hasNext()) {
          Map.Entry<Name, Object> entry = zentries.next();
          if (entry.getKey().equals(origin)) {
            continue;
          }
          RRset[] sets = allRRsets(entry.getValue());
          if (sets.length == 0) {
            continue;
          }
          current = sets;
          count = 0;
          break;
        }
      }
      return set;
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }

  @VisibleForTesting
  void setLock(ReentrantReadWriteLock.ReadLock lock) {
    readLock = lock;
  }

  private void validate() throws IOException, IllegalMonitorStateException {
    originNode = exactName(origin);
    if (originNode == null) {
      throw new IOException(origin + ": no data specified");
    }

    RRset rrset = oneRRset(originNode, Type.SOA);
    if (rrset == null || rrset.size() != 1) {
      throw new IOException(origin + ": exactly 1 SOA must be specified");
    }
    SOA = (SOARecord) rrset.rrs().get(0);

    NS = oneRRset(originNode, Type.NS);
    if (NS == null) {
      throw new IOException(origin + ": no NS set specified");
    }
  }

  private void maybeAddRecord(Record record) throws IOException, IllegalMonitorStateException {
    int rtype = record.getType();
    Name name = record.getName();

    if (rtype == Type.SOA && !name.equals(origin)) {
      throw new IOException("SOA owner " + name + " does not match zone origin " + origin);
    }
    if (name.subdomain(origin)) {
      addRecord(record);
    }
  }

  /**
   * Creates a Zone from the records in the specified master file.
   *
   * @param zone The name of the zone.
   * @param file The master file to read from.
   * @see Master
   */
  public Zone(Name zone, String file) throws IOException, IllegalMonitorStateException {
    writeLock.lock();
    data = new TreeMap<>();

    if (zone == null) {
      writeLock.unlock();
      throw new IllegalArgumentException("no zone name specified");
    }
    try (Master m = new Master(file, zone)) {
      Record record;

      origin = zone;
      while ((record = m.nextRecord()) != null) {
        maybeAddRecord(record);
      }
    }
    validate();
    writeLock.unlock();
  }

  /**
   * Creates a Zone from an array of records.
   *
   * @param zone The name of the zone.
   * @param records The records to add to the zone.
   * @see Master
   */
  public Zone(Name zone, Record[] records) throws IOException, IllegalMonitorStateException {
    writeLock.lock();
    data = new TreeMap<>();

    if (zone == null) {
      throw new IllegalArgumentException("no zone name specified");
    }
    origin = zone;
    for (Record record : records) {
      maybeAddRecord(record);
    }
    validate();
    writeLock.unlock();
  }

  private void fromXFR(ZoneTransferIn xfrin)
      throws IOException, ZoneTransferException, IllegalMonitorStateException {
    writeLock.lock();
    data = new TreeMap<>();

    origin = xfrin.getName();
    xfrin.run();
    if (!xfrin.isAXFR()) {
      writeLock.unlock();
      throw new IllegalArgumentException("zones can only be created from AXFRs");
    }

    for (Record record : xfrin.getAXFR()) {
      maybeAddRecord(record);
    }
    validate();
    writeLock.unlock();
  }

  /**
   * Creates a Zone by doing the specified zone transfer.
   *
   * @param xfrin The incoming zone transfer to execute.
   * @see ZoneTransferIn
   */
  public Zone(ZoneTransferIn xfrin)
      throws IOException, ZoneTransferException, IllegalMonitorStateException {
    fromXFR(xfrin);
  }

  /**
   * Creates a Zone by performing a zone transfer to the specified host.
   *
   * @see ZoneTransferIn
   */
  public Zone(Name zone, int dclass, String remote)
      throws IOException, ZoneTransferException, IllegalMonitorStateException {
    ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(zone, remote, null);
    xfrin.setDClass(dclass);
    fromXFR(xfrin);
  }

  /** Returns the Zone's origin */
  public Name getOrigin() {
    return origin;
  }

  /** Returns the Zone origin's NS records */
  public RRset getNS() {
    return NS;
  }

  /** Returns the Zone's SOA record */
  public SOARecord getSOA() {
    return SOA;
  }

  /** Returns the Zone's class */
  public int getDClass() {
    return DClass.IN;
  }

  private Object exactName(Name name) throws IllegalMonitorStateException {
    readLock.lock();
    Object val = data.get(name);
    readLock.unlock();
    return val;
  }

  private RRset[] allRRsets(Object types) throws IllegalMonitorStateException {
    if (types instanceof List) {
      readLock.lock();
      @SuppressWarnings("unchecked")
      List<RRset> typelist = (List<RRset>) types;
      readLock.unlock();
      return typelist.toArray(new RRset[0]);
    } else {
      RRset set = (RRset) types;
      return new RRset[] {set};
    }
  }

  private RRset oneRRset(Object types, int type) throws IllegalMonitorStateException {
    if (type == Type.ANY) {
      throw new IllegalArgumentException("oneRRset(ANY)");
    }
    readLock.lock();
    RRset resultSet = null;
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<RRset> list = (List<RRset>) types;
      for (RRset set : list) {
        if (set.getType() == type) {
          resultSet = set;
          break;
        }
      }
    } else {
      RRset set = (RRset) types;
      if (set.getType() == type) {
        resultSet = set;
      }
    }
    readLock.unlock();
    return resultSet;
  }

  private RRset findRRset(Name name, int type) {
    Object types = exactName(name);
    if (types == null) {
      return null;
    }
    return oneRRset(types, type);
  }

  private void addRRset(Name name, RRset rrset) throws IllegalMonitorStateException {
    writeLock.lock();
    if (!hasWild && name.isWild()) {
      hasWild = true;
    }
    Object types = data.get(name);
    if (types == null) {
      data.put(name, rrset);
      writeLock.unlock();
      return;
    }
    int rtype = rrset.getType();
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<RRset> list = (List<RRset>) types;
      for (int i = 0; i < list.size(); i++) {
        RRset set = list.get(i);
        if (set.getType() == rtype) {
          list.set(i, rrset);
          writeLock.unlock();
          return;
        }
      }
      list.add(rrset);
    } else {
      RRset set = (RRset) types;
      if (set.getType() == rtype) {
        data.put(name, rrset);
      } else {
        LinkedList<RRset> list = new LinkedList<>();
        list.add(set);
        list.add(rrset);
        data.put(name, list);
      }
    }
    writeLock.unlock();
  }

  private void removeRRset(Name name, int type) throws IllegalMonitorStateException {
    writeLock.lock();
    Object types = data.get(name);
    if (types == null) {
      writeLock.unlock();
      return;
    }
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<RRset> list = (List<RRset>) types;
      for (int i = 0; i < list.size(); i++) {
        RRset set = list.get(i);
        if (set.getType() == type) {
          list.remove(i);
          if (list.isEmpty()) {
            data.remove(name);
          }
          writeLock.unlock();
          return;
        }
      }
    } else {
      RRset set = (RRset) types;
      if (set.getType() != type) {
        writeLock.unlock();
        return;
      }
      data.remove(name);
    }
    writeLock.unlock();
  }

  private SetResponse lookup(Name name, int type) throws IllegalMonitorStateException {
    if (!name.subdomain(origin)) {
      return SetResponse.ofType(SetResponse.NXDOMAIN);
    }

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

      /* If this is a delegation, return that. */
      if (!isOrigin) {
        RRset ns = oneRRset(types, Type.NS);
        if (ns != null) {
          return new SetResponse(SetResponse.DELEGATION, ns);
        }
      }

      /* If this is an ANY lookup, return everything. */
      if (isExact && type == Type.ANY) {
        SetResponse sr = new SetResponse(SetResponse.SUCCESSFUL);
        for (RRset set : allRRsets(types)) {
          sr.addRRset(set);
        }
        return sr;
      }

      /*
       * If this is the name, look for the actual type or a CNAME.
       * Otherwise, look for a DNAME.
       */
      if (isExact) {
        RRset rrset = oneRRset(types, type);
        if (rrset != null) {
          return new SetResponse(SetResponse.SUCCESSFUL, rrset);
        }
        rrset = oneRRset(types, Type.CNAME);
        if (rrset != null) {
          return new SetResponse(SetResponse.CNAME, rrset);
        }
      } else {
        RRset rrset = oneRRset(types, Type.DNAME);
        if (rrset != null) {
          return new SetResponse(SetResponse.DNAME, rrset);
        }
      }

      /* We found the name, but not the type. */
      if (isExact) {
        return SetResponse.ofType(SetResponse.NXRRSET);
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
          SetResponse sr = new SetResponse(SetResponse.SUCCESSFUL);
          for (RRset set : allRRsets(types)) {
            sr.addRRset(expandSet(set, name));
          }
          return sr;
        } else {
          RRset rrset = oneRRset(types, type);
          if (rrset != null) {
            return new SetResponse(SetResponse.SUCCESSFUL, expandSet(rrset, name));
          }
        }
      }
    }

    return SetResponse.ofType(SetResponse.NXDOMAIN);
  }

  private RRset expandSet(RRset set, Name tname) {
    RRset expandedSet = new RRset();
    for (Record r : set.rrs()) {
      expandedSet.addRR(r.withName(tname));
    }
    for (RRSIGRecord r : set.sigs()) {
      expandedSet.addRR(r.withName(tname));
    }
    return expandedSet;
  }

  /**
   * Looks up Records in the Zone. The answer can be a {@code CNAME} instead of the actual requested
   * type and wildcards are expanded.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return A SetResponse object
   * @see SetResponse
   */
  public SetResponse findRecords(Name name, int type) throws IllegalMonitorStateException {
    return lookup(name, type);
  }

  /**
   * Looks up Records in the zone, finding exact matches only.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return The matching RRset
   * @see RRset
   */
  public RRset findExactMatch(Name name, int type) throws IllegalMonitorStateException {
    Object types = exactName(name);
    if (types == null) {
      return null;
    }
    return oneRRset(types, type);
  }

  /**
   * Adds an RRset to the Zone
   *
   * @param rrset The RRset to be added
   * @see RRset
   */
  public void addRRset(RRset rrset) throws IllegalMonitorStateException {
    writeLock.lock();
    Name name = rrset.getName();
    addRRset(name, rrset);
    writeLock.unlock();
  }

  /**
   * Adds a Record to the Zone
   *
   * @param r The record to be added
   * @see Record
   */
  public <T extends Record> void addRecord(T r) throws IllegalMonitorStateException {
    writeLock.lock();
    Name name = r.getName();
    int rtype = r.getRRsetType();
    RRset rrset = findRRset(name, rtype);
    if (rrset == null) {
      rrset = new RRset(r);
      addRRset(name, rrset);
    } else {
      rrset.addRR(r);
    }
    writeLock.unlock();
  }

  /**
   * Removes a record from the Zone
   *
   * @param r The record to be removed
   * @see Record
   */
  public void removeRecord(Record r) throws IllegalMonitorStateException {
    writeLock.lock();
    Name name = r.getName();
    int rtype = r.getRRsetType();
    RRset rrset = findRRset(name, rtype);
    if (rrset == null) {
      return;
    }
    if (rrset.size() == 1 && rrset.first().equals(r)) {
      removeRRset(name, rtype);
    } else {
      rrset.deleteRR(r);
    }
    writeLock.unlock();
  }

  /** Returns an Iterator over the RRsets in the zone. */
  public Iterator<RRset> iterator() throws IllegalMonitorStateException {
    return new ZoneIterator(false);
  }

  /**
   * Returns an Iterator over the RRsets in the zone that can be used to construct an AXFR response.
   * This is identical to {@link #iterator} except that the SOA is returned at the end as well as
   * the beginning.
   */
  public Iterator<RRset> AXFR() throws IllegalMonitorStateException {
    return new ZoneIterator(true);
  }

  private void nodeToString(StringBuilder sb, Object node) throws IllegalMonitorStateException {
    RRset[] sets = allRRsets(node);
    for (RRset rrset : sets) {
      rrset.rrs().forEach(r -> sb.append(r).append('\n'));
      rrset.sigs().forEach(r -> sb.append(r).append('\n'));
    }
  }

  /** Returns the contents of the Zone in master file format. */
  public String toMasterFile() throws IllegalMonitorStateException {
    readLock.lock();
    StringBuilder sb = new StringBuilder();
    nodeToString(sb, originNode);
    for (Map.Entry<Name, Object> entry : data.entrySet()) {
      if (!origin.equals(entry.getKey())) {
        nodeToString(sb, entry.getValue());
      }
    }
    readLock.unlock();
    return sb.toString();
  }

  /** Returns the contents of the Zone as a string (in master file format). */
  @Override
  public String toString() throws IllegalMonitorStateException {
    return toMasterFile();
  }
}

// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * A set of Records with the same name, type, and class. Also included are all RRSIG records signing
 * the data records.
 *
 * @see Record
 * @see RRSIGRecord
 * @author Brian Wellington
 */
public class RRset implements Serializable {
  private final ArrayList<Record> rrs;
  private final ArrayList<RRSIGRecord> sigs;
  private short position;
  private long ttl;

  /** Creates an empty RRset */
  public RRset() {
    rrs = new ArrayList<>(1);
    sigs = new ArrayList<>(0);
  }

  /** Creates an RRset and sets its contents to the specified record */
  public RRset(Record record) {
    this();
    addRR(record);
  }

  /** Creates an RRset with the contents of an existing RRset */
  public RRset(RRset rrset) {
    rrs = new ArrayList<>(rrset.rrs);
    sigs = new ArrayList<>(rrset.sigs);
    position = rrset.position;
    ttl = rrset.ttl;
  }

  /**
   * Adds a signature to this RRset. If the TTL of the added signature is not the same as existing
   * records in the RRset, all records are set to the lowest TTL of either the added record or the
   * existing records.
   */
  public void addRR(RRSIGRecord r) {
    addRR(r, sigs);
  }

  /**
   * Adds a Record to this RRset. If the TTL of the added record is not the same as existing records
   * in the RRset, all records are set to the lowest TTL of either the added record or the existing
   * records.
   */
  public void addRR(Record r) {
    if (r instanceof RRSIGRecord) {
      addRR((RRSIGRecord) r, sigs);
      return;
    }

    addRR(r, rrs);
  }

  @SuppressWarnings("unchecked")
  private <X extends Record> void addRR(final X r, List<X> rs) {
    if (sigs.isEmpty() && rrs.isEmpty()) {
      rs.add(r);
      ttl = r.getTTL();
      return;
    }

    checkSameRRset(r, rrs);
    checkSameRRset(r, sigs);

    // rfc2181#section-5.2:
    // [...] treat the RRs for all purposes as if all TTLs in the
    // RRSet had been set to the value of the lowest TTL in the RRSet.
    X copy = r;
    if (copy.getTTL() > ttl) {
      copy = (X) r.cloneRecord();
      copy.setTTL(ttl);
    } else if (copy.getTTL() < ttl) {
      ttl = copy.getTTL();
      adjustTtl(copy.getTTL(), rrs);
      adjustTtl(copy.getTTL(), sigs);
    }

    if (!rs.contains(copy)) {
      rs.add(copy);
    }
  }

  private <X extends Record> void adjustTtl(long ttl, List<X> rs) {
    for (int i = 0; i < rs.size(); i++) {
      @SuppressWarnings("unchecked")
      X tmp = (X) rs.get(i).cloneRecord();
      tmp.setTTL(ttl);
      rs.set(i, tmp);
    }
  }

  private void checkSameRRset(Record r, List<? extends Record> rs) {
    if (rs.isEmpty()) {
      return;
    }

    if (!r.sameRRset(rs.get(0))) {
      throw new IllegalArgumentException("record does not match rrset");
    }
  }

  /** Deletes a signature from this RRset */
  public void deleteRR(RRSIGRecord r) {
    sigs.remove(r);
  }

  /** Deletes a record from this RRset */
  public void deleteRR(Record r) {
    if (r instanceof RRSIGRecord) {
      sigs.remove(r);
      return;
    }

    rrs.remove(r);
  }

  /** Deletes all records (including signatures) from this RRset */
  public void clear() {
    rrs.clear();
    sigs.clear();
  }

  /**
   * Returns a list of all data records.
   *
   * @param cycle If true, cycle through the records so that each list will start with a different
   *     record.
   */
  public List<Record> rrs(boolean cycle) {
    if (!cycle || rrs.size() <= 1) {
      return Collections.unmodifiableList(rrs);
    }

    List<Record> l = new ArrayList<>(rrs.size());
    if (position == Short.MAX_VALUE) {
      position = 0;
    }
    int start = position++ % rrs.size();
    l.addAll(rrs.subList(start, rrs.size()));
    l.addAll(rrs.subList(0, start));
    return l;
  }

  /**
   * Returns a list of all data records. This cycles through the records, so that each returned list
   * will start with a different record.
   */
  public List<Record> rrs() {
    return rrs(true);
  }

  /** Returns a list of all signature records. */
  public List<RRSIGRecord> sigs() {
    return Collections.unmodifiableList(sigs);
  }

  /** Returns the number of (data) records */
  public int size() {
    return rrs.size();
  }

  /**
   * Returns the name of the records
   *
   * @see Name
   */
  public Name getName() {
    return first().getName();
  }

  /**
   * Returns the type of the records
   *
   * @see Type
   */
  public int getType() {
    return first().getRRsetType();
  }

  /**
   * Returns the class of the records
   *
   * @see DClass
   */
  public int getDClass() {
    return first().getDClass();
  }

  /** Returns the ttl of the records */
  public long getTTL() {
    return first().getTTL();
  }

  /**
   * Returns the first record in this RRset, either an RR or a signature.
   *
   * @throws IllegalStateException if the RRset is empty
   */
  public Record first() {
    if (!rrs.isEmpty()) {
      return rrs.get(0);
    }
    if (!sigs.isEmpty()) {
      return sigs.get(0);
    }

    throw new IllegalStateException("rrset is empty");
  }

  private void appendRrList(Iterator<? extends Record> it, StringBuilder sb) {
    while (it.hasNext()) {
      Record rr = it.next();
      sb.append("[");
      sb.append(rr.rdataToString());
      sb.append("]");
      if (it.hasNext()) {
        sb.append(" ");
      }
    }
  }

  /** Converts the RRset to a String */
  @Override
  public String toString() {
    if (rrs.isEmpty() && sigs.isEmpty()) {
      return "{empty}";
    }

    StringBuilder sb = new StringBuilder();
    sb.append("{ ");
    sb.append(getName()).append(" ");
    sb.append(getTTL()).append(" ");
    sb.append(DClass.string(getDClass())).append(" ");
    sb.append(Type.string(getType())).append(" ");
    appendRrList(rrs.iterator(), sb);
    if (!sigs.isEmpty()) {
      sb.append(" sigs: ");
      appendRrList(sigs.iterator(), sb);
    }

    sb.append(" }");
    return sb.toString();
  }
}

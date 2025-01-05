// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2003-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;

/**
 * A helper class for constructing dynamic DNS (DDNS) update messages.
 *
 * @author Brian Wellington
 */
public class Update extends Message {

  private final Name origin;
  private final int dclass;

  /**
   * Creates an update message.
   *
   * @param zone The name of the zone being updated.
   * @param dclass The class of the zone being updated.
   */
  public Update(Name zone, int dclass) {
    super();
    if (!zone.isAbsolute()) {
      throw new RelativeNameException(zone);
    }
    DClass.check(dclass);
    getHeader().setOpcode(Opcode.UPDATE);
    Record soa = Record.newRecord(zone, Type.SOA, DClass.IN);
    addRecord(soa, Section.QUESTION);
    this.origin = zone;
    this.dclass = dclass;
  }

  /**
   * Creates an update message. The class is assumed to be IN.
   *
   * @param zone The name of the zone being updated.
   */
  public Update(Name zone) {
    this(zone, DClass.IN);
  }

  private void newPrereq(Record rec) {
    addRecord(rec, Section.PREREQ);
  }

  private void newUpdate(Record rec) {
    addRecord(rec, Section.UPDATE);
  }

  /**
   * Inserts a prerequisite that the specified name exists; that is, there exist records with the
   * given name in the zone.
   */
  public void present(Name name) {
    newPrereq(Record.newRecord(name, Type.ANY, DClass.ANY, 0));
  }

  /**
   * Inserts a prerequisite that the specified rrset exists; that is, there exist records with the
   * given name and type in the zone.
   */
  public void present(Name name, int type) {
    newPrereq(Record.newRecord(name, type, DClass.ANY, 0));
  }

  /**
   * Parses a record from the string, and inserts a prerequisite that the record exists. Due to the
   * way value-dependent prequisites work, the condition that must be met is that the set of all
   * records with the same and type in the update message must be identical to the set of all
   * records with that name and type on the server.
   *
   * @throws IOException The record could not be parsed.
   */
  public void present(Name name, int type, String recordToCheck) throws IOException {
    newPrereq(Record.fromString(name, type, dclass, 0, recordToCheck, origin));
  }

  /**
   * Parses a record from the tokenizer, and inserts a prerequisite that the record exists. Due to
   * the way value-dependent prequisites work, the condition that must be met is that the set of all
   * records with the same and type in the update message must be identical to the set of all
   * records with that name and type on the server.
   *
   * @throws IOException The record could not be parsed.
   */
  public void present(Name name, int type, Tokenizer tokenizer) throws IOException {
    newPrereq(Record.fromString(name, type, dclass, 0, tokenizer, origin));
  }

  /**
   * Inserts a prerequisite that the specified record exists. Due to the way value-dependent
   * prequisites work, the condition that must be met is that the set of all records with the same
   * and type in the update message must be identical to the set of all records with that name and
   * type on the server.
   */
  public void present(Record recordToCheck) {
    newPrereq(recordToCheck);
  }

  /**
   * Inserts a prerequisite that the specified name does not exist; that is, there are no records
   * with the given name in the zone.
   */
  public void absent(Name name) {
    newPrereq(Record.newRecord(name, Type.ANY, DClass.NONE, 0));
  }

  /**
   * Inserts a prerequisite that the specified rrset does not exist; that is, there are no records
   * with the given name and type in the zone.
   */
  public void absent(Name name, int type) {
    newPrereq(Record.newRecord(name, type, DClass.NONE, 0));
  }

  /**
   * Parses a record from the string, and indicates that the record should be inserted into the
   * zone.
   *
   * @throws IOException The record could not be parsed.
   */
  public void add(Name name, int type, long ttl, String recordToAdd) throws IOException {
    newUpdate(Record.fromString(name, type, dclass, ttl, recordToAdd, origin));
  }

  /**
   * Parses a record from the tokenizer, and indicates that the record should be inserted into the
   * zone.
   *
   * @throws IOException The record could not be parsed.
   */
  public void add(Name name, int type, long ttl, Tokenizer tokenizer) throws IOException {
    newUpdate(Record.fromString(name, type, dclass, ttl, tokenizer, origin));
  }

  /** Indicates that the record should be inserted into the zone. */
  public void add(Record recordToAdd) {
    newUpdate(recordToAdd);
  }

  /** Indicates that the records should be inserted into the zone. */
  public void add(Record[] records) {
    for (Record r : records) {
      add(r);
    }
  }

  /** Indicates that all the records in the rrset should be inserted into the zone. */
  public <T extends Record> void add(RRset rrset) {
    rrset.rrs().forEach(this::add);
  }

  /** Indicates that all records with the given name should be deleted from the zone. */
  public void delete(Name name) {
    newUpdate(Record.newRecord(name, Type.ANY, DClass.ANY, 0));
  }

  /** Indicates that all records with the given name and type should be deleted from the zone. */
  public void delete(Name name, int type) {
    newUpdate(Record.newRecord(name, type, DClass.ANY, 0));
  }

  /**
   * Parses a record from the string, and indicates that the record should be deleted from the zone.
   *
   * @throws IOException The record could not be parsed.
   */
  public void delete(Name name, int type, String recordToDelete) throws IOException {
    newUpdate(Record.fromString(name, type, DClass.NONE, 0, recordToDelete, origin));
  }

  /**
   * Parses a record from the tokenizer, and indicates that the record should be deleted from the
   * zone.
   *
   * @throws IOException The record could not be parsed.
   */
  public void delete(Name name, int type, Tokenizer tokenizer) throws IOException {
    newUpdate(Record.fromString(name, type, DClass.NONE, 0, tokenizer, origin));
  }

  /** Indicates that the specified record should be deleted from the zone. */
  public void delete(Record recordToDelete) {
    newUpdate(recordToDelete.withDClass(DClass.NONE, 0));
  }

  /** Indicates that the records should be deleted from the zone. */
  public void delete(Record[] records) {
    for (Record r : records) {
      delete(r);
    }
  }

  /** Indicates that all of the records in the rrset should be deleted from the zone. */
  public <T extends Record> void delete(RRset rrset) {
    rrset.rrs().forEach(this::delete);
  }

  /**
   * Parses a record from the string, and indicates that the record should be inserted into the zone
   * replacing any other records with the same name and type.
   *
   * @throws IOException The record could not be parsed.
   */
  public void replace(Name name, int type, long ttl, String recordToReplace) throws IOException {
    delete(name, type);
    add(name, type, ttl, recordToReplace);
  }

  /**
   * Parses a record from the tokenizer, and indicates that the record should be inserted into the
   * zone replacing any other records with the same name and type.
   *
   * @throws IOException The record could not be parsed.
   */
  public void replace(Name name, int type, long ttl, Tokenizer tokenizer) throws IOException {
    delete(name, type);
    add(name, type, ttl, tokenizer);
  }

  /**
   * Indicates that the record should be inserted into the zone replacing any other records with the
   * same name and type.
   */
  public void replace(Record recordToReplace) {
    delete(recordToReplace.getName(), recordToReplace.getType());
    add(recordToReplace);
  }

  /**
   * Indicates that the records should be inserted into the zone replacing any other records with
   * the same name and type as each one.
   */
  public void replace(Record[] records) {
    for (Record r : records) {
      replace(r);
    }
  }

  /**
   * Indicates that all the records in the rrset should be inserted into the zone replacing any
   * other records with the same name and type.
   */
  public <T extends Record> void replace(RRset rrset) {
    delete(rrset.getName(), rrset.getType());
    rrset.rrs().forEach(this::add);
  }
}

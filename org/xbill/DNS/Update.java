// Copyright (c) 2003 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A helper class for constructing dynamic DNS (DDNS) update messages.
 *
 * @author Brian Wellington
 */

public class Update extends Message {

private Name origin;
private short dclass;

/**
 * Creates an update message.
 * @param zone The name of the zone being updated.
 * @param dclass The class of the zone being updated.
 */
public
Update(Name zone, short dclass) {
	super();
        getHeader().setOpcode(Opcode.UPDATE);
	Record soa = Record.newRecord(zone, Type.SOA, DClass.IN);
	addRecord(soa, Section.QUESTION);
	this.origin = zone;
	this.dclass = dclass;
}

/**
 * Creates an update message.  The class is assumed to be IN.
 * @param zone The name of the zone being updated.
 */
public
Update(Name zone) {
	this(zone, DClass.IN);
}

private void
newPrereq(Record rec) {
	addRecord(rec, Section.PREREQ);
}

private void
newUpdate(Record rec) {
	addRecord(rec, Section.UPDATE);
}

/**
 * Inserts a prerequisite that the specified name exists; that is, there
 * exist records with the given name in the zone.
 */
public void
present(Name name) {
	newPrereq(Record.newRecord(name, Type.ANY, DClass.ANY, 0));
}

/**
 * Inserts a prerequisite that the specified rrset exists; that is, there
 * exist records with the given name and type in the zone.
 */
public void
present(Name name, short type) {
	newPrereq(Record.newRecord(name, type, DClass.ANY, 0));
}

/**
 * Parses a record from the string, and inserts a prerequisite that the
 * record exists.  Due to the way value-dependent prequisites work, the
 * condition that must be met is that the set of all records with the same 
 * and type in the update message must be identical to the set of all records
 * with that name and type on the server.
 * @throws IOException The record could not be parsed.
 */
public void
present(Name name, short type, String record) throws IOException {
	newPrereq(Record.fromString(name, type, dclass, 0, record, origin));
}

/**
 * Parses a record from the tokenizer, and inserts a prerequisite that the
 * record exists.  Due to the way value-dependent prequisites work, the
 * condition that must be met is that the set of all records with the same 
 * and type in the update message must be identical to the set of all records
 * with that name and type on the server.
 * @throws IOException The record could not be parsed.
 */
public void
present(Name name, short type, Tokenizer tokenizer) throws IOException {
	newPrereq(Record.fromString(name, type, dclass, 0, tokenizer, origin));
}

/**
 * Inserts a prerequisite that the specified record exists.  Due to the way
 * value-dependent prequisites work, the condition that must be met is that
 * the set of all records with the same and type in the update message must
 * be identical to the set of all records with that name and type on the server.
 */
public void
present(Record record) {
	newPrereq(record);
}

/**
 * Inserts a prerequisite that the specified name does not exist; that is,
 * there are no records with the given name in the zone.
 */
public void
absent(Name name) {
	newPrereq(Record.newRecord(name, Type.ANY, DClass.NONE, 0));
}

/**
 * Inserts a prerequisite that the specified rrset does not exist; that is,
 * there are no records with the given name and type in the zone.
 */
public void
absent(Name name, short type) {
	newPrereq(Record.newRecord(name, type, DClass.NONE, 0));
}

/**
 * Parses a record from the string, and indicates that the record
 * should be inserted into the zone.
 * @throws IOException The record could not be parsed.
 */
public void
add(Name name, short type, int ttl, String record) throws IOException {
	newUpdate(Record.fromString(name, type, dclass, ttl, record, origin));
}

/**
 * Parses a record from the tokenizer, and indicates that the record
 * should be inserted into the zone.
 * @throws IOException The record could not be parsed.
 */
public void
add(Name name, short type, int ttl, Tokenizer tokenizer) throws IOException {
	newUpdate(Record.fromString(name, type, dclass, ttl, tokenizer,
				    origin));
}

/**
 * Indicates that the record should be inserted into the zone.
 */
public void
add(Record record) {
	newUpdate(record);
}

/**
 * Indicates that all records with the given name should be deleted from
 * the zone.
 */
public void
delete(Name name) {
	newUpdate(Record.newRecord(name, Type.ANY, DClass.ANY, 0));
}

/**
 * Indicates that all records with the given name and type should be deleted
 * from the zone.
 */
public void
delete(Name name, short type) {
	newUpdate(Record.newRecord(name, type, DClass.ANY, 0));
}

/**
 * Parses a record from the string, and indicates that the record
 * should be deleted from the zone.
 * @throws IOException The record could not be parsed.
 */
public void
delete(Name name, short type, String record) throws IOException {
	newUpdate(Record.fromString(name, type, DClass.NONE, 0, record,
				    origin));
}

/**
 * Parses a record from the tokenizer, and indicates that the record
 * should be deleted from the zone.
 * @throws IOException The record could not be parsed.
 */
public void
delete(Name name, short type, Tokenizer tokenizer) throws IOException {
	newUpdate(Record.fromString(name, type, DClass.NONE, 0, tokenizer,
				    origin));
}

/**
 * Indicates that the specified record should be deleted from the zone.
 */
public void
delete(Record record) {
	newUpdate(record);
}

/**
 * Parses a record from the string, and indicates that the record
 * should be inserted into the zone replacing any other records with the
 * same name and type.
 * @throws IOException The record could not be parsed.
 */
public void
replace(Name name, short type, int ttl, String record) throws IOException {
	delete(name, type);
	newUpdate(Record.fromString(name, type, dclass, ttl, record, origin));
}

/**
 * Parses a record from the tokenizer, and indicates that the record
 * should be inserted into the zone replacing any other records with the
 * same name and type.
 * @throws IOException The record could not be parsed.
 */
public void
replace(Name name, short type, int ttl, Tokenizer tokenizer) throws IOException
{
	delete(name, type);
	newUpdate(Record.fromString(name, type, dclass, ttl, tokenizer,
				    origin));
}

/**
 * Indicates that the record should be inserted into the zone replacing any
 * other records with the same name and type.
 */
public void
replace(Record record) {
	delete(record.getName(), record.getType());
	newUpdate(record);
}



}

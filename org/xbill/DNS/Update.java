// Copyright (c) 2003 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.util.*;

/**
 * A helper class for constructing dynamic DNS (DDNS) update messages.
 *
 * @author Brian Wellington
 */

public class Update {

private Name origin;
private short dclass;
private Message message;

/**
 * Creates an update message.
 * @param zone The name of the zone being updated.
 * @param dclass The class of the zone being updated.
 */
public
Update(Name zone, short dclass) {
	this.origin = zone;
	this.dclass = dclass;
	this.message = Message.newUpdate(zone);
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
	message.addRecord(rec, Section.PREREQ);
}

private void
newUpdate(Record rec) {
	message.addRecord(rec, Section.UPDATE);
}

/**
 * Inserts a prerequisite that the specified name exists; that is, there
 * exist records with the given name in the zone.
 */
public void
nameExists(Name name) {
	newPrereq(Record.newRecord(name, Type.ANY, DClass.ANY, 0));
}

/**
 * Inserts a prerequisite that the specified rrset exists; that is, there
 * exist records with the given name and type in the zone.
 */
public void
rrsetExists(Name name, short type) {
	newPrereq(Record.newRecord(name, type, DClass.ANY, 0));
}

/**
 * Parses a record from the string, and inserts a prerequisite that the
 * record exists.  Due to the way value-dependent prequisites work, the
 * condition that must be met is that the set of all records with the same 
 * and type in the update message must be identical to the set of all records
 * with that name and type on the server.
 */
public void
recordExists(Name name, short type, String record) throws IOException {
	newPrereq(Record.fromString(name, type, dclass, 0, record, origin));
}

/**
 * Parses a record from the tokenizer, and inserts a prerequisite that the
 * record exists.  Due to the way value-dependent prequisites work, the
 * condition that must be met is that the set of all records with the same 
 * and type in the update message must be identical to the set of all records
 * with that name and type on the server.
 */
public void
recordExists(Name name, short type, Tokenizer tokenizer) throws IOException {
	newPrereq(Record.fromString(name, type, dclass, 0, tokenizer, origin));
}

/**
 * Inserts a prerequisite that the specified record exists.  Due to the way
 * value-dependent prequisites work, the condition that must be met is that
 * the set of all records with the same and type in the update message must
 * be identical to the set of all records with that name and type on the server.
 */
public void
recordExists(Record record) throws IOException {
	newPrereq(record);
}

/**
 * Inserts a prerequisite that the specified name does not exist; that is,
 * there are no records with the given name in the zone.
 */
public void
nameDoesNotExist(Name name) {
	newPrereq(Record.newRecord(name, Type.ANY, DClass.NONE, 0));
}

/**
 * Inserts a prerequisite that the specified rrset does not exist; that is,
 * there are no records with the given name and type in the zone.
 */
public void
rrsetDoesNotExist(Name name, short type) {
	newPrereq(Record.newRecord(name, type, DClass.NONE, 0));
}

/**
 * Parses a record from the string, and indicates that the record
 * should be inserted into the zone.
 */
public void
addRecord(Name name, short type, int ttl, String record) throws IOException {
	newUpdate(Record.fromString(name, type, dclass, ttl, record, origin));
}

/**
 * Parses a record from the tokenizer, and indicates that the record
 * should be inserted into the zone.
 */
public void
addRecord(Name name, short type, int ttl, Tokenizer tokenizer)
throws IOException
{
	newUpdate(Record.fromString(name, type, dclass, ttl, tokenizer,
				    origin));
}

/**
 * Indicates that the record should be inserted into the zone.
 */
public void
addRecord(Record record) throws IOException {
	newUpdate(record);
}

/**
 * Indicates that all records with the given name should be deleted from
 * the zone.
 */
public void
deleteName(Name name) {
	newUpdate(Record.newRecord(name, Type.ANY, DClass.ANY, 0));
}

/**
 * Indicates that all records with the given name and type should be deleted
 * from the zone.
 */
public void
deleteRRset(Name name, short type) {
	newUpdate(Record.newRecord(name, type, DClass.ANY, 0));
}

/**
 * Parses a record from the string, and indicates that the record
 * should be deleted from the zone.
 */
public void
deleteRecord(Name name, short type, String record) throws IOException {
	newUpdate(Record.fromString(name, type, DClass.NONE, 0, record,
				    origin));
}

/**
 * Parses a record from the tokenizer, and indicates that the record
 * should be deleted from the zone.
 */
public void
deleteRecord(Name name, short type, Tokenizer tokenizer) throws IOException
{
	newUpdate(Record.fromString(name, type, DClass.NONE, 0, tokenizer,
				    origin));
}

/**
 * Indicates that the specified record should be deleted from the zone.
 */
public void
deleteRecord(Record record) throws IOException {
	newUpdate(record);
}

/**
 * Returns the update message.  This may be called at any time after the update
 * has been created.
 */
public Message
getMessage() {
	return message;
}

}

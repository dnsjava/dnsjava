// Copyright (c) 2003 Brian Wellington (bwelling@xbill.org)
// Parts of this are derived from lib/dns/xfrin.c from BIND 9; its copyright
// notice follows.

/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package org.xbill.DNS;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * An incoming DNS Zone Transfer.  To use this class, first initialize an
 * object, then call the run() method.  If run() doesn't throw an exception
 * the result will either be an IXFR-style response, an AXFR-style response,
 * or an indication that the zone is up to date.
 *
 * @author Brian Wellington
 */

public class ZoneTransferIn {

private static final int INITIALSOA	= 0;
private static final int FIRSTDATA	= 1;
private static final int IXFR_DELSOA	= 2;
private static final int IXFR_DEL	= 3;
private static final int IXFR_ADDSOA	= 4;
private static final int IXFR_ADD	= 5;
private static final int AXFR		= 6;
private static final int END		= 7;

private SimpleResolver res;
private Name zname;
private short qtype;
private int ixfr_serial;
private boolean want_fallback;

private SimpleResolver.Stream stream;

private int state;
private int end_serial;
private int current_serial;
private Record initialsoa;

private int rtype;

private List axfr;
private List ixfr;

public static class Delta {
	/**
	 * All changes between two versions of a zone in an IXFR response.
	 */

	/** The starting serial number of this delta. */
	public int start;

	/** The ending serial number of this delta. */
	public int end;

	/** A list of records added between the start and end versions */
	public List adds;

	/** A list of records deleted between the start and end versions */
	public List deletes;

	private
	Delta() {
		adds = new ArrayList();
		deletes = new ArrayList();
	}
}

private
ZoneTransferIn() {}

private
ZoneTransferIn(SimpleResolver sres, Name zone, short xfrtype,
	       int serial, boolean fallback)
{
	res = sres;
	if (zone.isAbsolute())
		zname = zone;
	else {
		try {
			zname = Name.concatenate(zone, Name.root);
		}
		catch (NameTooLongException e) {
			throw new IllegalArgumentException("ZoneTransferIn: " +
							   "name too long");
		}
	}
	qtype = xfrtype;
	ixfr_serial = serial;
	want_fallback = fallback;
	state = INITIALSOA;
}

private static SimpleResolver
newResolver(String host, int port, TSIG key) throws UnknownHostException {
	SimpleResolver sres = new SimpleResolver(host);
	if (port != 0)
		sres.setPort(port);
	if (key != null)
		sres.setTSIGKey(key);
	return sres;
}

/**
 * Instantiates a ZoneTransferIn object to do an AXFR (full zone transfer).
 * @param zone The zone to transfer.
 * @param res The resolver to use when doing the transfer.
 * @return The ZoneTransferIn object.
 */
public static ZoneTransferIn
newAXFR(Name zone, SimpleResolver res) {
	return new ZoneTransferIn(res, zone, Type.AXFR, 0, false);
}

/**
 * Instantiates a ZoneTransferIn object to do an AXFR (full zone transfer).
 * @param zone The zone to transfer.
 * @param host The host from which to transfer the zone.
 * @param port The port to connect to on the server, or 0 for the default.
 * @param key The TSIG key used to authenticate the transfer, or null.
 * @return The ZoneTransferIn object.
 * @throws UnknownHostException The host does not exist.
 */
public static ZoneTransferIn
newAXFR(Name zone, String host, int port, TSIG key)
throws UnknownHostException
{
	return newAXFR(zone, newResolver(host, port, key));
}

/**
 * Instantiates a ZoneTransferIn object to do an AXFR (full zone transfer).
 * @param zone The zone to transfer.
 * @param host The host from which to transfer the zone.
 * @param key The TSIG key used to authenticate the transfer, or null.
 * @return The ZoneTransferIn object.
 * @throws UnknownHostException The host does not exist.
 */
public static ZoneTransferIn
newAXFR(Name zone, String host, TSIG key)
throws UnknownHostException
{
	return newAXFR(zone, newResolver(host, 0, key));
}

/**
 * Instantiates a ZoneTransferIn object to do an IXFR (incremental zone
 * transfer).
 * @param zone The zone to transfer.
 * @param serial The existing serial number.
 * @param fallback If true, fall back to AXFR if IXFR is not supported.
 * @param res The resolver to use when doing the transfer.
 * @return The ZoneTransferIn object.
 */
public static ZoneTransferIn
newIXFR(Name zone, int serial, boolean fallback, SimpleResolver res) {
	return new ZoneTransferIn(res, zone, Type.IXFR, serial, fallback);
}

/**
 * Instantiates a ZoneTransferIn object to do an IXFR (incremental zone
 * transfer).
 * @param zone The zone to transfer.
 * @param serial The existing serial number.
 * @param fallback If true, fall back to AXFR if IXFR is not supported.
 * @param host The host from which to transfer the zone.
 * @param port The port to connect to on the server, or 0 for the default.
 * @param key The TSIG key used to authenticate the transfer, or null.
 * @return The ZoneTransferIn object.
 * @throws UnknownHostException The host does not exist.
 */
public static ZoneTransferIn
newIXFR(Name zone, int serial, boolean fallback,
	String host, int port, TSIG key)
throws UnknownHostException
{
	return newIXFR(zone, serial, fallback, newResolver(host, port, key));
}

/**
 * Instantiates a ZoneTransferIn object to do an IXFR (incremental zone
 * transfer).
 * @param zone The zone to transfer.
 * @param serial The existing serial number.
 * @param fallback If true, fall back to AXFR if IXFR is not supported.
 * @param host The host from which to transfer the zone.
 * @param key The TSIG key used to authenticate the transfer, or null.
 * @return The ZoneTransferIn object.
 * @throws UnknownHostException The host does not exist.
 */
public static ZoneTransferIn
newIXFR(Name zone, int serial, boolean fallback, String host, TSIG key)
throws UnknownHostException
{
	return newIXFR(zone, serial, fallback, newResolver(host, 0, key));
}

private void
openConnection() throws IOException {
	stream = new SimpleResolver.Stream(res);
}

private void
sendQuery() throws IOException {
	Record question = Record.newRecord(zname, qtype, DClass.IN);

	Message query = new Message();
	query.getHeader().setOpcode(Opcode.QUERY);
	query.addRecord(question, Section.QUESTION);
	if (qtype == Type.IXFR) {
		Record soa = new SOARecord(zname, DClass.IN, 0, Name.root,
					   Name.root, (int)ixfr_serial,
					   0, 0, 0, 0);
		query.addRecord(soa, Section.AUTHORITY);
	}
	stream.send(query);
}

private int
getSOASerial(Record rec) {
	SOARecord soa = (SOARecord) rec;
	return soa.getSerial();
}

private void
logxfr(String s) {
	if (Options.check("verbose"))
		System.out.println(zname + ": " + s);
}

private void
fail(String s) throws ZoneTransferException {
	throw new ZoneTransferException(s);
}

private void
fallback() throws ZoneTransferException {
	if (!want_fallback)
		fail("server doesn't support IXFR");

	logxfr("falling back to AXFR");
	qtype = Type.AXFR;
	state = INITIALSOA;
	closeConnection();
}

private void
parseRR(Record rec) throws ZoneTransferException {
	Name name = rec.getName();
	short type = rec.getType();
	Delta delta;

	switch (state) {
	case INITIALSOA:
		if (type != Type.SOA)
			fail("missing initial SOA");
		initialsoa = rec;
		// Remember the serial number in the intial SOA; we need it
		// to recognize the end of an IXFR.
		end_serial = getSOASerial(rec);
		if (qtype == Type.IXFR && end_serial <= ixfr_serial) {
			logxfr("up to date");
			state = END;
			break;
		}
		state = FIRSTDATA;
		break;

	case FIRSTDATA:
		// If the transfer begins with 1 SOA, it's an AXFR.
		// If it begins with 2 SOAs, it's an IXFR.
		if (qtype == Type.IXFR && type == Type.SOA &&
		    getSOASerial(rec) == ixfr_serial)
		{
			rtype = Type.IXFR;
			ixfr = new ArrayList();
			logxfr("got incremental response");
			state = IXFR_DELSOA;
		} else {
			rtype = Type.AXFR;
			axfr = new ArrayList();
			axfr.add(initialsoa);
			logxfr("got nonincremental response");
			state = AXFR;
		}
		parseRR(rec); // Restart...
		return;

	case IXFR_DELSOA:
		delta = new Delta();
		ixfr.add(delta);
		delta.start = getSOASerial(rec);
		delta.deletes.add(rec);
		state = IXFR_DEL;
		break;

	case IXFR_DEL:
		if (type == Type.SOA) {
			current_serial = getSOASerial(rec);
			state = IXFR_ADDSOA;
			parseRR(rec); // Restart...
			return;
		}
		delta = (Delta) ixfr.get(ixfr.size() - 1);
		delta.deletes.add(rec);
		break;

	case IXFR_ADDSOA:
		delta = (Delta) ixfr.get(ixfr.size() - 1);
		delta.end = getSOASerial(rec);
		delta.adds.add(rec);
		state = IXFR_ADD;
		break;

	case IXFR_ADD:
		if (type == Type.SOA) {
			int soa_serial = getSOASerial(rec);
			if (soa_serial == end_serial) {
				state = END;
				break;
			} else if (soa_serial != current_serial) {
				fail("IXFR out of sync: expected serial " +
				     current_serial + " , got " + soa_serial);
			} else {
				state = IXFR_DELSOA;
				parseRR(rec); // Restart...
				return;
			}
		}
		delta = (Delta) ixfr.get(ixfr.size() - 1);
		delta.adds.add(rec);
		break;

	case AXFR:
		// Old BINDs sent cross class A records for non IN classes.
		if (type == Type.A && rec.getDClass() != DClass.IN)
			break;
		axfr.add(rec);
		if (type == Type.SOA) {
			state = END;
		}
		break;

	case END:
		fail("extra data");
		break;

	default:
		fail("invalid state");
		break;
	}
}

private void
closeConnection() {
	stream.close();
}

private void
doxfr() throws IOException, ZoneTransferException {
	sendQuery();
	while (state != END) {
		Message response;
		Record [] answers;

		response = stream.next();
		answers = response.getSectionArray(Section.ANSWER);

		if (state == INITIALSOA) {
			int rcode = response.getRcode();
			if (rcode != Rcode.NOERROR) {
				if (qtype == Type.IXFR &&
				    rcode == Rcode.NOTIMPL)
				{
					fallback();
					run();
					return;
				}
				fail(Rcode.string(rcode));
			}

			Record question = response.getQuestion();
			if (question != null && question.getType() != qtype) {
				fail("invalid question section");
			}

			if (answers.length == 0 && qtype == Type.IXFR) {
				fallback();
				run();
				return;
			}
		}

		for (int i = 0; i < answers.length; i++) {
			parseRR(answers[i]);
		}
	}
}

/**
 * Does the zone transfer.
 * @return A list, which is either an AXFR-style response (List of Records),
 * and IXFR-style response (List of Deltas), or null, which indicates that
 * an IXFR was performed and the zone is up to date.
 * @throws IOException The zone transfer failed to due an IO problem.
 * @throws ZoneTransferException The zone transfer failed to due a problem
 * with the zone transfer itself.
 */
public List
run() throws IOException, ZoneTransferException {
	openConnection();
	try {
		doxfr();
	}
	finally {
		closeConnection();
	}
	if (axfr != null)
		return axfr;
	if (ixfr != null)
		return ixfr;
	return null;
}

/**
 * Returns true if the response is an AXFR-style response (List of Records).
 * This will be true if either an IXFR was performed, an IXFR was performed
 * and the server provided a full zone transfer, or an IXFR failed and
 * fallback to AXFR occurred.
 */
public boolean
isAXFR() {
	return (rtype == Type.AXFR);
}

/**
 * Gets the AXFR-style response.
 */
public List
getAXFR() {
	return axfr;
}

/**
 * Returns true if the response is an IXFR-style response (List of Deltas).
 * This will be true only if an IXFR was performed and the server provided
 * an incremental zone transfer.
 */
public boolean
isIXFR() {
	return (rtype == Type.IXFR);
}

/**
 * Gets the IXFR-style response.
 */
public List
getIXFR() {
	return ixfr;
}

/**
 * Returns true if the response indicates that the zone is up to date.
 * This will be true only if an IXFR was performed.
 */
public boolean
isCurrent() {
	return (axfr == null && ixfr == null);
}

}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2003-2004 Brian Wellington (bwelling@xbill.org)
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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

/**
 * An incoming DNS Zone Transfer. To use this class, first initialize an object, then call the run()
 * method. If run() doesn't throw an exception the result will either be an IXFR-style response, an
 * AXFR-style response, or an indication that the zone is up to date.
 *
 * @author Brian Wellington
 */
@Slf4j
public class ZoneTransferIn {

  private static final int INITIALSOA = 0;
  private static final int FIRSTDATA = 1;
  private static final int IXFR_DELSOA = 2;
  private static final int IXFR_DEL = 3;
  private static final int IXFR_ADDSOA = 4;
  private static final int IXFR_ADD = 5;
  private static final int AXFR = 6;
  private static final int END = 7;

  private final Name zname;
  private int qtype;
  private int dclass;
  private final long ixfrSerial;
  private final boolean wantFallback;
  private ZoneTransferHandler handler;

  private SocketAddress localAddress;
  private final SocketAddress address;
  private TCPClient client;
  private final TSIG tsig;
  private TSIG.StreamVerifier verifier;
  private Duration timeout = Duration.ofMinutes(15);

  private int state;
  private long endSerial;
  private long currentSerial;
  private Record initialSoaRecord;

  private int rtype;

  /** All changes between two versions of a zone in an IXFR response. */
  public static class Delta {

    /** The starting serial number of this delta. */
    public long start;

    /** The ending serial number of this delta. */
    public long end;

    /** A list of records added between the start and end versions */
    public List<Record> adds;

    /** A list of records deleted between the start and end versions */
    public List<Record> deletes;

    private Delta() {
      adds = new ArrayList<>();
      deletes = new ArrayList<>();
    }
  }

  /** Handles a Zone Transfer. */
  public interface ZoneTransferHandler {

    /** Called when an AXFR transfer begins. */
    void startAXFR() throws ZoneTransferException;

    /** Called when an IXFR transfer begins. */
    void startIXFR() throws ZoneTransferException;

    /**
     * Called when a series of IXFR deletions begins.
     *
     * @param soa The starting SOA.
     */
    void startIXFRDeletes(Record soa) throws ZoneTransferException;

    /**
     * Called when a series of IXFR adds begins.
     *
     * @param soa The starting SOA.
     */
    void startIXFRAdds(Record soa) throws ZoneTransferException;

    /**
     * Called for each content record in an AXFR.
     *
     * @param r The DNS record.
     */
    void handleRecord(Record r) throws ZoneTransferException;
  }

  private static class BasicHandler implements ZoneTransferHandler {
    private List<Record> axfr;
    private List<Delta> ixfr;

    @Override
    public void startAXFR() {
      axfr = new ArrayList<>();
    }

    @Override
    public void startIXFR() {
      ixfr = new ArrayList<>();
    }

    @Override
    public void startIXFRDeletes(Record soa) {
      Delta delta = new Delta();
      delta.deletes.add(soa);
      delta.start = getSOASerial(soa);
      ixfr.add(delta);
    }

    @Override
    public void startIXFRAdds(Record soa) {
      Delta delta = ixfr.get(ixfr.size() - 1);
      delta.adds.add(soa);
      delta.end = getSOASerial(soa);
    }

    @Override
    public void handleRecord(Record r) {
      if (ixfr != null) {
        Delta delta = ixfr.get(ixfr.size() - 1);
        if (!delta.adds.isEmpty()) {
          delta.adds.add(r);
        } else {
          delta.deletes.add(r);
        }
      } else {
        axfr.add(r);
      }
    }
  }

  ZoneTransferIn(
      Name zone, int xfrtype, long serial, boolean fallback, SocketAddress address, TSIG key) {
    this.address = address;
    this.tsig = key;
    if (zone.isAbsolute()) {
      zname = zone;
    } else {
      try {
        zname = Name.concatenate(zone, Name.root);
      } catch (NameTooLongException e) {
        throw new IllegalArgumentException("ZoneTransferIn: name too long");
      }
    }
    qtype = xfrtype;
    dclass = DClass.IN;
    ixfrSerial = serial;
    wantFallback = fallback;
    state = INITIALSOA;
  }

  /**
   * Instantiates a ZoneTransferIn object to do an AXFR (full zone transfer).
   *
   * @param zone The zone to transfer.
   * @param address The host/port from which to transfer the zone.
   * @param key The TSIG key used to authenticate the transfer, or null.
   * @return The ZoneTransferIn object.
   */
  public static ZoneTransferIn newAXFR(Name zone, SocketAddress address, TSIG key) {
    return new ZoneTransferIn(zone, Type.AXFR, 0, false, address, key);
  }

  /**
   * Instantiates a ZoneTransferIn object to do an AXFR (full zone transfer).
   *
   * @param zone The zone to transfer.
   * @param host The host from which to transfer the zone.
   * @param port The port to connect to on the server, or 0 for the default.
   * @param key The TSIG key used to authenticate the transfer, or null.
   * @return The ZoneTransferIn object.
   */
  public static ZoneTransferIn newAXFR(Name zone, String host, int port, TSIG key) {
    if (port == 0) {
      port = SimpleResolver.DEFAULT_PORT;
    }
    return newAXFR(zone, new InetSocketAddress(host, port), key);
  }

  /**
   * Instantiates a ZoneTransferIn object to do an AXFR (full zone transfer).
   *
   * @param zone The zone to transfer.
   * @param host The host from which to transfer the zone.
   * @param key The TSIG key used to authenticate the transfer, or null.
   * @return The ZoneTransferIn object.
   */
  public static ZoneTransferIn newAXFR(Name zone, String host, TSIG key) {
    return newAXFR(zone, host, 0, key);
  }

  /**
   * Instantiates a ZoneTransferIn object to do an IXFR (incremental zone transfer).
   *
   * @param zone The zone to transfer.
   * @param serial The existing serial number.
   * @param fallback If true, fall back to AXFR if IXFR is not supported.
   * @param address The host/port from which to transfer the zone.
   * @param key The TSIG key used to authenticate the transfer, or null.
   * @return The ZoneTransferIn object.
   */
  public static ZoneTransferIn newIXFR(
      Name zone, long serial, boolean fallback, SocketAddress address, TSIG key) {
    return new ZoneTransferIn(zone, Type.IXFR, serial, fallback, address, key);
  }

  /**
   * Instantiates a ZoneTransferIn object to do an IXFR (incremental zone transfer).
   *
   * @param zone The zone to transfer.
   * @param serial The existing serial number.
   * @param fallback If true, fall back to AXFR if IXFR is not supported.
   * @param host The host from which to transfer the zone.
   * @param port The port to connect to on the server, or 0 for the default.
   * @param key The TSIG key used to authenticate the transfer, or null.
   * @return The ZoneTransferIn object.
   */
  public static ZoneTransferIn newIXFR(
      Name zone, long serial, boolean fallback, String host, int port, TSIG key) {
    if (port == 0) {
      port = SimpleResolver.DEFAULT_PORT;
    }
    return newIXFR(zone, serial, fallback, new InetSocketAddress(host, port), key);
  }

  /**
   * Instantiates a ZoneTransferIn object to do an IXFR (incremental zone transfer).
   *
   * @param zone The zone to transfer.
   * @param serial The existing serial number.
   * @param fallback If true, fall back to AXFR if IXFR is not supported.
   * @param host The host from which to transfer the zone.
   * @param key The TSIG key used to authenticate the transfer, or null.
   * @return The ZoneTransferIn object.
   */
  public static ZoneTransferIn newIXFR(
      Name zone, long serial, boolean fallback, String host, TSIG key) {
    return newIXFR(zone, serial, fallback, host, 0, key);
  }

  /** Gets the name of the zone being transferred. */
  public Name getName() {
    return zname;
  }

  /** Gets the type of zone transfer (either AXFR or IXFR). */
  public int getType() {
    return qtype;
  }

  /**
   * Sets a timeout on this zone transfer. The default is 900 seconds (15 minutes).
   *
   * @param secs The maximum amount of time that this zone transfer can take.
   * @deprecated use {@link #setTimeout(Duration)}
   */
  @Deprecated
  public void setTimeout(int secs) {
    if (secs < 0) {
      throw new IllegalArgumentException("timeout cannot be negative");
    }
    timeout = Duration.ofSeconds(secs);
  }

  /**
   * Sets a timeout on this zone transfer. The default is 900 seconds (15 minutes).
   *
   * @param t The maximum amount of time that this zone transfer can take.
   */
  public void setTimeout(Duration t) {
    timeout = t;
  }

  /**
   * Sets an alternate DNS class for this zone transfer.
   *
   * @param dclass The class to use instead of class IN.
   */
  public void setDClass(int dclass) {
    DClass.check(dclass);
    this.dclass = dclass;
  }

  /**
   * Sets the local address to bind to when sending messages.
   *
   * @param addr The local address to send messages from.
   */
  public void setLocalAddress(SocketAddress addr) {
    this.localAddress = addr;
  }

  private void openConnection() throws IOException {
    client = createTcpClient(timeout);
    if (localAddress != null) {
      client.bind(localAddress);
    }
    client.connect(address);
  }

  TCPClient createTcpClient(Duration timeout) throws IOException {
    return new TCPClient(timeout);
  }

  private void sendQuery() throws IOException {
    Record question = Record.newRecord(zname, qtype, dclass);

    Message query = new Message();
    query.getHeader().setOpcode(Opcode.QUERY);
    query.addRecord(question, Section.QUESTION);
    if (qtype == Type.IXFR) {
      Record soa = new SOARecord(zname, dclass, 0, Name.root, Name.root, ixfrSerial, 0, 0, 0, 0);
      query.addRecord(soa, Section.AUTHORITY);
    }
    if (tsig != null) {
      tsig.apply(query, null);
      verifier = new TSIG.StreamVerifier(tsig, query.getTSIG());
    }
    byte[] out = query.toWire(Message.MAXLENGTH);
    client.send(out);
  }

  private static long getSOASerial(Record rec) {
    SOARecord soa = (SOARecord) rec;
    return soa.getSerial();
  }

  private void logxfr(String s) {
    log.debug("{}: {}", zname, s);
  }

  private void fail(String s) throws ZoneTransferException {
    throw new ZoneTransferException(s);
  }

  private void fallback() throws ZoneTransferException {
    if (!wantFallback) {
      fail("server doesn't support IXFR");
    }

    logxfr("falling back to AXFR");
    qtype = Type.AXFR;
    state = INITIALSOA;
  }

  private void parseRR(Record rec) throws ZoneTransferException {
    int type = rec.getType();

    switch (state) {
      case INITIALSOA:
        if (type != Type.SOA) {
          fail("missing initial SOA");
        }
        initialSoaRecord = rec;
        // Remember the serial number in the initial SOA; we need it
        // to recognize the end of an IXFR.
        endSerial = getSOASerial(rec);
        if (qtype == Type.IXFR && Serial.compare(endSerial, ixfrSerial) <= 0) {
          logxfr("up to date");
          state = END;
          break;
        }
        state = FIRSTDATA;
        break;

      case FIRSTDATA:
        // If the transfer begins with 1 SOA, it's an AXFR.
        // If it begins with 2 SOAs, it's an IXFR.
        if (qtype == Type.IXFR && type == Type.SOA && getSOASerial(rec) == ixfrSerial) {
          rtype = Type.IXFR;
          handler.startIXFR();
          logxfr("got incremental response");
          state = IXFR_DELSOA;
        } else {
          rtype = Type.AXFR;
          handler.startAXFR();
          handler.handleRecord(initialSoaRecord);
          logxfr("got nonincremental response");
          state = AXFR;
        }
        parseRR(rec); // Restart...
        return;

      case IXFR_DELSOA:
        handler.startIXFRDeletes(rec);
        state = IXFR_DEL;
        break;

      case IXFR_DEL:
        if (type == Type.SOA) {
          currentSerial = getSOASerial(rec);
          state = IXFR_ADDSOA;
          parseRR(rec); // Restart...
          return;
        }
        handler.handleRecord(rec);
        break;

      case IXFR_ADDSOA:
        handler.startIXFRAdds(rec);
        state = IXFR_ADD;
        break;

      case IXFR_ADD:
        if (type == Type.SOA) {
          long soa_serial = getSOASerial(rec);
          if (soa_serial == endSerial) {
            state = END;
            break;
          } else if (soa_serial != currentSerial) {
            fail("IXFR out of sync: expected serial " + currentSerial + " , got " + soa_serial);
          } else {
            state = IXFR_DELSOA;
            parseRR(rec); // Restart...
            return;
          }
        }
        handler.handleRecord(rec);
        break;

      case AXFR:
        // Old BINDs sent cross class A records for non IN classes.
        if (type == Type.A && rec.getDClass() != dclass) {
          break;
        }
        handler.handleRecord(rec);
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

  private void closeConnection() {
    try {
      if (client != null) {
        client.close();
      }
    } catch (IOException e) {
      // Ignore
    }
  }

  private Message parseMessage(byte[] b) throws WireParseException {
    try {
      return new Message(b);
    } catch (IOException e) {
      if (e instanceof WireParseException) {
        throw (WireParseException) e;
      }
      throw new WireParseException("Error parsing message", e);
    }
  }

  private void doxfr() throws IOException, ZoneTransferException {
    sendQuery();
    while (state != END) {
      byte[] in = client.recv();
      Message response = parseMessage(in);
      List<Record> answers = response.getSection(Section.ANSWER);
      if (response.getHeader().getRcode() == Rcode.NOERROR && verifier != null) {
        int error =
            verifier.verify(response, in, answers.get(answers.size() - 1).getType() == Type.SOA);
        if (error != Rcode.NOERROR) {
          if (verifier.getErrorMessage() != null) {
            fail(
                "TSIG failure: "
                    + Rcode.TSIGstring(error)
                    + " ("
                    + verifier.getErrorMessage()
                    + ")");
          } else {
            fail("TSIG failure: " + Rcode.TSIGstring(error));
          }
        }
      }

      if (state == INITIALSOA) {
        int rcode = response.getRcode();
        if (rcode != Rcode.NOERROR) {
          if (qtype == Type.IXFR && rcode == Rcode.NOTIMP) {
            fallback();
            doxfr();
            return;
          }
          fail(Rcode.string(rcode));
        }

        Record question = response.getQuestion();
        if (question != null && question.getType() != qtype) {
          fail("invalid question section");
        }

        if (answers.isEmpty() && qtype == Type.IXFR) {
          fallback();
          doxfr();
          return;
        }
      }

      for (Record answer : answers) {
        parseRR(answer);
      }
    }
  }

  /**
   * Does the zone transfer.
   *
   * @param handler The callback object that handles the zone transfer data.
   * @throws IOException The zone transfer failed to due an IO problem.
   * @throws ZoneTransferException The zone transfer failed to due a problem with the zone transfer
   *     itself.
   */
  public void run(ZoneTransferHandler handler) throws IOException, ZoneTransferException {
    this.handler = handler;
    try {
      openConnection();
      doxfr();
    } finally {
      closeConnection();
    }
  }

  /**
   * Does the zone transfer using an internal handler. Results can be obtained by calling {@link
   * #getAXFR()} or getIXFR
   *
   * @throws IOException The zone transfer failed to due an IO problem.
   * @throws ZoneTransferException The zone transfer failed to due a problem with the zone transfer
   *     itself.
   */
  public void run() throws IOException, ZoneTransferException {
    BasicHandler basicHandler = new BasicHandler();
    run(basicHandler);
  }

  private BasicHandler getBasicHandler() throws IllegalArgumentException {
    if (handler instanceof BasicHandler) {
      return (BasicHandler) handler;
    }
    throw new IllegalArgumentException("ZoneTransferIn used callback interface");
  }

  /**
   * Returns true if the response is an AXFR-style response (List of Records). This will be true if
   * either an IXFR was performed, an IXFR was performed and the server provided a full zone
   * transfer, or an IXFR failed and fallback to AXFR occurred.
   */
  public boolean isAXFR() {
    return rtype == Type.AXFR;
  }

  /**
   * Gets the AXFR-style response.
   *
   * @throws IllegalArgumentException The transfer used the callback interface, so the response was
   *     not stored.
   */
  public List<Record> getAXFR() {
    BasicHandler basicHandler = getBasicHandler();
    return basicHandler.axfr;
  }

  /**
   * Returns true if the response is an IXFR-style response (List of Deltas). This will be true only
   * if an IXFR was performed and the server provided an incremental zone transfer.
   */
  public boolean isIXFR() {
    return rtype == Type.IXFR;
  }

  /**
   * Gets the IXFR-style response.
   *
   * @throws IllegalArgumentException The transfer used the callback interface, so the response was
   *     not stored.
   */
  public List<Delta> getIXFR() {
    BasicHandler basicHandler = getBasicHandler();
    return basicHandler.ixfr;
  }

  /**
   * Returns true if the response indicates that the zone is up to date. This will be true only if
   * an IXFR was performed.
   *
   * @throws IllegalArgumentException The transfer used the callback interface, so the response was
   *     not stored.
   */
  public boolean isCurrent() {
    BasicHandler basicHandler = getBasicHandler();
    return basicHandler.axfr == null && basicHandler.ixfr == null;
  }
}

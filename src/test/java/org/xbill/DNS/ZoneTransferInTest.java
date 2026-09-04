// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ZoneTransferInTest {

  private Name zoneName;
  private SocketAddress address;

  @BeforeEach
  void setUp() throws TextParseException {
    zoneName = Name.fromString("example.com.");
    address = new InetSocketAddress("127.0.0.1", 53);
  }

  @Test
  void testNewAXFR() {
    ZoneTransferIn xfr = ZoneTransferIn.newAXFR(zoneName, address, null);
    assertEquals(zoneName, xfr.getName());
    assertEquals(Type.AXFR, xfr.getType());
  }

  @Test
  void testNewIXFR() {
    ZoneTransferIn xfr = ZoneTransferIn.newIXFR(zoneName, 12345L, true, address, null);
    assertEquals(zoneName, xfr.getName());
    assertEquals(Type.IXFR, xfr.getType());
  }

  @Test
  void testSetters() {
    ZoneTransferIn xfr = ZoneTransferIn.newAXFR(zoneName, address, null);
    assertThatCode(() -> xfr.setTimeout(Duration.ofSeconds(10))).doesNotThrowAnyException();
    assertThatCode(() -> xfr.setDClass(DClass.CH)).doesNotThrowAnyException();
    assertThatCode(() -> xfr.setLocalAddress(new InetSocketAddress("127.0.0.2", 0))).doesNotThrowAnyException();
  }

  @Test
  void testInvalidDClass() {
    ZoneTransferIn xfr = ZoneTransferIn.newAXFR(zoneName, address, null);
    assertThrows(InvalidDClassException.class, () -> xfr.setDClass(-1));
  }

  private static class MockTCPClient extends TCPClient {
    private final List<byte[]> responses;
    private int responseIndex = 0;

    MockTCPClient(Duration timeout, List<byte[]> responses) throws IOException {
      super(timeout);
      this.responses = responses;
    }

    @Override
    public void connect(SocketAddress addr) {}

    @Override
    public void bind(SocketAddress addr) {}

    @Override
    public void send(byte[] data) {
    }

    @Override
    byte[] recv() throws IOException {
      if (responseIndex >= responses.size()) {
        throw new IOException("No more mock responses");
      }
      return responses.get(responseIndex++);
    }

    @Override
    public void close() {}
  }

  private static class TestZoneTransferIn extends ZoneTransferIn {
    private final List<byte[]> responses;

    TestZoneTransferIn(
        Name zone,
        int type,
        long serial,
        boolean fallback,
        SocketAddress address,
        List<byte[]> responses) {
      super(zone, type, serial, fallback, address, null);
      this.responses = responses;
    }

    @Override
    TCPClient createTcpClient(Duration timeout) throws IOException {
      return new MockTCPClient(timeout, responses);
    }
  }

  @Test
  void testAXFRSuccess() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 1, 3600, 600, 86400, 3600);
    ARecord a = new ARecord(name, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));

    Message m = new Message();
    m.getHeader().setID(1); // doesn't matter much
    m.addRecord(soa, Section.ANSWER);
    m.addRecord(a, Section.ANSWER);
    m.addRecord(soa, Section.ANSWER);

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.AXFR, 0, false, address, responses);
    xfr.run();

    assertTrue(xfr.isAXFR());
    List<Record> records = xfr.getAXFR();
    assertEquals(3, records.size());
    assertEquals(soa, records.get(0));
    assertEquals(a, records.get(1));
    assertEquals(soa, records.get(2));
  }

  @Test
  void testIXFRSuccess() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa1 =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 1, 3600, 600, 86400, 3600);
    SOARecord soa2 =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 2, 3600, 600, 86400, 3600);
    ARecord a = new ARecord(name, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));

    Message m = new Message();
    m.addRecord(soa2, Section.ANSWER); // Current SOA
    m.addRecord(soa1, Section.ANSWER); // Deleted SOA
    m.addRecord(a, Section.ANSWER); // Deleted record
    m.addRecord(soa2, Section.ANSWER); // Added SOA
    m.addRecord(a, Section.ANSWER); // Added record
    m.addRecord(soa2, Section.ANSWER); // End of IXFR

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, false, address, responses);
    xfr.run();

    assertTrue(xfr.isIXFR());
    List<ZoneTransferIn.Delta> deltas = xfr.getIXFR();
    assertEquals(1, deltas.size());
    ZoneTransferIn.Delta delta = deltas.get(0);
    assertEquals(1, delta.start);
    assertEquals(2, delta.end);
    assertEquals(2, delta.deletes.size());
    assertEquals(soa1, delta.deletes.get(0));
    assertEquals(a, delta.deletes.get(1));
    assertEquals(2, delta.adds.size());
    assertEquals(soa2, delta.adds.get(0));
    assertEquals(a, delta.adds.get(1));
  }

  @Test
  void testIXFRUpToDate() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa1 =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 1, 3600, 600, 86400, 3600);

    Message m = new Message();
    m.addRecord(soa1, Section.ANSWER);

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, false, address, responses);
    xfr.run();

    assertTrue(xfr.isCurrent());
  }

  @Test
  void testIXFRFallbackToAXFR() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 2, 3600, 600, 86400, 3600);

    Message mNotImp = new Message();
    mNotImp.getHeader().setRcode(Rcode.NOTIMP);

    Message mAxfr = new Message();
    mAxfr.addRecord(soa, Section.ANSWER);
    mAxfr.addRecord(soa, Section.ANSWER);

    List<byte[]> responses = new ArrayList<>();
    responses.add(mNotImp.toWire());
    responses.add(mAxfr.toWire());

    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, true, address, responses);
    xfr.run();

    assertTrue(xfr.isAXFR());
    assertEquals(2, xfr.getAXFR().size());
  }

  @Test
  void testMissingInitialSOA() throws IOException {
    Name name = Name.fromString("example.com.");
    ARecord a = new ARecord(name, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));

    Message m = new Message();
    m.addRecord(a, Section.ANSWER);

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.AXFR, 0, false, address, responses);
    assertThrows(ZoneTransferException.class, xfr::run);
  }

  @Test
  void testExtraData() throws IOException {
    Name name = Name.fromString("example.com.");
    SOARecord soa =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 1, 3600, 600, 86400, 3600);

    Message m = new Message();
    m.addRecord(soa, Section.ANSWER);
    m.addRecord(soa, Section.ANSWER);
    m.addRecord(soa, Section.ANSWER); // One too many for AXFR state machine if not careful

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.AXFR, 0, false, address, responses);
    assertThrows(ZoneTransferException.class, xfr::run);
  }

  @Test
  void testRcodeError() throws IOException {
    Name name = Name.fromString("example.com.");
    Message m = new Message();
    m.getHeader().setRcode(Rcode.REFUSED);

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.AXFR, 0, false, address, responses);
    ZoneTransferException exception = assertThrows(ZoneTransferException.class, xfr::run);
    assertTrue(exception.getMessage().contains("REFUSED"));
  }

  @Test
  void testIXFRAsAXFR() throws IOException, ZoneTransferException {
    // Server returns AXFR response (single SOA) to IXFR query
    Name name = Name.fromString("example.com.");
    SOARecord soa =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 2, 3600, 600, 86400, 3600);

    Message m = new Message();
    m.addRecord(soa, Section.ANSWER);
    m.addRecord(soa, Section.ANSWER);

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, false, address, responses);
    xfr.run();

    assertTrue(xfr.isAXFR());
    assertEquals(2, xfr.getAXFR().size());
  }

  @Test
  void testMultipleMessages() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 1, 3600, 600, 86400, 3600);
    ARecord a1 = new ARecord(name, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));
    ARecord a2 = new ARecord(name, DClass.IN, 3600, InetAddress.getByName("127.0.0.2"));

    Message m1 = new Message();
    m1.addRecord(soa, Section.ANSWER);
    m1.addRecord(a1, Section.ANSWER);

    Message m2 = new Message();
    m2.addRecord(a2, Section.ANSWER);
    m2.addRecord(soa, Section.ANSWER);

    List<byte[]> responses = new ArrayList<>();
    responses.add(m1.toWire());
    responses.add(m2.toWire());

    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.AXFR, 0, false, address, responses);
    xfr.run();

    assertTrue(xfr.isAXFR());
    List<Record> records = xfr.getAXFR();
    assertEquals(4, records.size());
    assertEquals(soa, records.get(0));
    assertEquals(a1, records.get(1));
    assertEquals(a2, records.get(2));
    assertEquals(soa, records.get(3));
  }

  @Test
  void testIXFREmptyResponseFallback() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 2, 3600, 600, 86400, 3600);

    Message mEmpty = new Message();
    // No records in ANSWER section

    Message mAxfr = new Message();
    mAxfr.addRecord(soa, Section.ANSWER);
    mAxfr.addRecord(soa, Section.ANSWER);

    List<byte[]> responses = new ArrayList<>();
    responses.add(mEmpty.toWire());
    responses.add(mAxfr.toWire());

    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, true, address, responses);
    xfr.run();

    assertTrue(xfr.isAXFR());
    assertEquals(2, xfr.getAXFR().size());
  }

  @Test
  void testTimeout() throws IOException {
    Name name = Name.fromString("example.com.");
    List<byte[]> responses =
        new ArrayList<>(); // Empty list will cause MockTCPClient to throw IOException

    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.AXFR, 0, false, address, responses);
    assertThrows(IOException.class, xfr::run);
  }

  @Test
  void testIsCurrent() throws IOException, ZoneTransferException {
    Name name = Name.fromString("example.com.");
    SOARecord soa1 =
        new SOARecord(name, DClass.IN, 3600, Name.root, Name.root, 1, 3600, 600, 86400, 3600);

    Message m = new Message();
    m.addRecord(soa1, Section.ANSWER);

    List<byte[]> responses = Collections.singletonList(m.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, false, address, responses);
    xfr.run();

    assertTrue(xfr.isCurrent());
    assertFalse(xfr.isAXFR());
    assertFalse(xfr.isIXFR());
  }


  @Test
  void testIXFRNoFallback() throws IOException {
    Name name = Name.fromString("example.com.");
    Message mNotImp = new Message();
    mNotImp.getHeader().setRcode(Rcode.NOTIMP);

    List<byte[]> responses = Collections.singletonList(mNotImp.toWire());
    TestZoneTransferIn xfr = new TestZoneTransferIn(name, Type.IXFR, 1, false, address, responses);
    assertThrows(ZoneTransferException.class, xfr::run);
  }
}

package org.xbill.DNS.tools;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Cache;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

class LookupToolTest {
  private final PrintStream originalOut = System.out;
  private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();

  @BeforeEach
  void setUp() {
    System.setOut(new PrintStream(outContent));
  }

  @AfterEach
  void tearDown() {
    System.setOut(originalOut);
  }

  @Test
  void testPrintAnswerSuccessful() throws TextParseException, UnknownHostException {
    Name name = Name.fromString("example.com.");
    Cache cache = new Cache();
    Record a = new ARecord(name, DClass.IN, 3600, InetAddress.getByName("127.0.0.1"));
    cache.addRecord(a, Credibility.AUTH_ANSWER, null);

    Lookup l = new Lookup(name, Type.A);
    l.setCache(cache);
    l.run();

    lookup.printAnswer("example.com", l);

    String output = outContent.toString();
    assertTrue(output.contains("example.com:"));
    assertTrue(output.contains("127.0.0.1"));
  }

  @Test
  void testPrintAnswerNotFound() throws TextParseException {
    Name name = Name.fromString("nonexistent.example.com.");
    // Use an empty cache and no resolver to ensure it fails
    Lookup l = new Lookup(name, Type.A);
    l.setCache(new Cache());
    // Don't set resolver to null, let it use default or a mock if we had one.
    // Since we don't have a network, it should eventually fail with "network error" or "host not found"
    // but without a resolver it throws NPE.
    l.run();

    lookup.printAnswer("example.com", l);

    String output = outContent.toString();
    assertTrue(output.contains("example.com:"));
  }

  @Test
  void testMainInvalidType() {
    assertThrows(IllegalArgumentException.class, () -> lookup.main(new String[] {"-t", "INVALID", "example.com"}));
  }

  @Test
  void testMainNoArgs() {
    assertDoesNotThrow(() -> lookup.main(new String[] {}));
  }
}

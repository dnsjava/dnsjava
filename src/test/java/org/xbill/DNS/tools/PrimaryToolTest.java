package org.xbill.DNS.tools;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PrimaryToolTest {
  private final PrintStream originalOut = System.out;
  private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();

  @TempDir
  File tempDir;

  @BeforeEach
  void setUp() {
    System.setOut(new PrintStream(outContent));
  }

  @AfterEach
  void tearDown() {
    System.setOut(originalOut);
  }

  @Test
  void testPrimary() throws Exception {
    File zoneFile = new File(tempDir, "example.com.zone");
    try (FileWriter writer = new FileWriter(zoneFile)) {
      writer.write("example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n");
      writer.write("example.com. 3600 IN NS ns1.example.com.\n");
      writer.write("ns1.example.com. 3600 IN A 127.0.0.1\n");
    }

    primary.main(new String[] {"example.com.", zoneFile.getAbsolutePath()});

    String output = outContent.toString();
    assertTrue(output.contains("example.com."));
    assertTrue(output.contains("SOA"));
    assertTrue(output.contains("ns1.example.com."));
  }

  @Test
  void testPrimaryAxfr() throws Exception {
    File zoneFile = new File(tempDir, "example.com.zone");
    try (FileWriter writer = new FileWriter(zoneFile)) {
      writer.write("example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n");
      writer.write("example.com. 3600 IN NS ns1.example.com.\n");
    }

    primary.main(new String[] {"-a", "example.com.", zoneFile.getAbsolutePath()});

    String output = outContent.toString();
    assertTrue(output.contains("SOA"));
    assertTrue(output.contains("NS"));
  }
}

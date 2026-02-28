// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.hosts;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.BufferedWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.spi.FileSystemProvider;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;
import org.apache.commons.io.file.spi.FileSystemProviders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

class HostsFileParserTest {
  private static final Name kubernetesName = Name.fromConstantString("kubernetes.docker.internal.");
  private static final byte[] localhostBytes = new byte[] {127, 0, 0, 1};
  private static Path hostsFileWindows;
  private static Path hostsFileInvalid;
  private static InetAddress kubernetesAddress;

  @TempDir Path tempDir;

  @BeforeAll
  static void beforeAll() throws URISyntaxException, UnknownHostException {
    hostsFileWindows = Paths.get(HostsFileParserTest.class.getResource("/hosts_example").toURI());
    hostsFileInvalid = Paths.get(HostsFileParserTest.class.getResource("/hosts_invalid").toURI());
    kubernetesAddress = InetAddress.getByAddress(kubernetesName.toString(), localhostBytes);
  }

  @Test
  void testArguments() {
    assertThrows(NullPointerException.class, () -> new HostsFileParser(null));
    assertThrows(IllegalArgumentException.class, () -> new HostsFileParser(tempDir));
  }

  @Test
  void handleNoValidClock() {
    HostsFileParser p = new HostsFileParser(hostsFileWindows);
    p.setClock(Clock.fixed(Instant.MIN, ZoneId.systemDefault()));
    assertDoesNotThrow(() -> p.getAddressForHost(Name.root, Type.A));
  }

  @Test
  void handleNoModificationTime() throws IOException {
    FileSystemProvider spiedFsp = spy(FileSystemProviders.getFileSystemProvider(hostsFileWindows));
    doAnswer(
            a -> {
              BasicFileAttributes attributes = spy((BasicFileAttributes) a.callRealMethod());
              when(attributes.lastModifiedTime()).thenReturn(FileTime.from(Instant.MIN));
              return attributes;
            })
        .when(spiedFsp)
        .readAttributes(any(), eq(BasicFileAttributes.class));
    Path spiedPath = spy(spiedFsp.getPath(hostsFileWindows.toUri()));
    when(spiedPath.getFileSystem())
        .thenAnswer(
            a -> {
              FileSystem spiedFs = spy((FileSystem) a.callRealMethod());
              doReturn(spiedFsp).when(spiedFs).provider();
              return spiedFs;
            });
    HostsFileParser p = new HostsFileParser(spiedPath);
    assertDoesNotThrow(() -> p.getAddressForHost(Name.root, Type.A));
  }

  @Test
  void testLookupType() {
    HostsFileParser hostsFileParser = new HostsFileParser(hostsFileWindows);
    assertThrows(
        IllegalArgumentException.class,
        () -> hostsFileParser.getAddressForHost(kubernetesName, Type.MX));
  }

  @Test
  void testEntireFileParsing() throws IOException {
    HostsFileParser hostsFileParser = new HostsFileParser(hostsFileWindows);
    assertEquals(
        kubernetesAddress,
        hostsFileParser
            .getAddressForHost(kubernetesName, Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
  }

  @Test
  void testMissingFileIsEmptyResult() throws IOException {
    HostsFileParser hostsFileParser = new HostsFileParser(tempDir.resolve("missing"));
    assertEquals(Optional.empty(), hostsFileParser.getAddressForHost(kubernetesName, Type.A));
  }

  @Test
  void testCacheLookupAfterFileDeleteWithoutChangeChecking() throws IOException {
    Path tempHosts = Files.copy(hostsFileWindows, tempDir, StandardCopyOption.REPLACE_EXISTING);
    HostsFileParser hostsFileParser = new HostsFileParser(tempHosts, false);
    assertEquals(0, hostsFileParser.cacheSize());
    assertEquals(
        kubernetesAddress,
        hostsFileParser
            .getAddressForHost(kubernetesName, Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
    assertTrue(hostsFileParser.cacheSize() > 1, "Cache must not be empty");
    Files.delete(tempHosts);
    assertEquals(
        kubernetesAddress,
        hostsFileParser
            .getAddressForHost(kubernetesName, Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
  }

  @Test
  void testFileDeletionClearsCache() throws IOException {
    Path tempHosts =
        Files.copy(
            hostsFileWindows,
            tempDir.resolve("testFileWatcherClearsCache"),
            StandardCopyOption.REPLACE_EXISTING);
    HostsFileParser hostsFileParser = new HostsFileParser(tempHosts);
    Clock clock = mock(Clock.class);
    hostsFileParser.setClock(clock);
    Instant now = Clock.systemUTC().instant();
    when(clock.instant()).thenReturn(now);
    assertEquals(0, hostsFileParser.cacheSize());
    assertEquals(
        kubernetesAddress,
        hostsFileParser
            .getAddressForHost(kubernetesName, Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
    assertTrue(hostsFileParser.cacheSize() > 1, "Cache must not be empty");
    Files.delete(tempHosts);
    when(clock.instant()).thenReturn(now.plus(Duration.ofMinutes(6)));
    assertEquals(Optional.empty(), hostsFileParser.getAddressForHost(kubernetesName, Type.A));
    assertEquals(0, hostsFileParser.cacheSize());
  }

  @Test
  void testFileChangeClearsCache() throws IOException {
    Path tempHosts =
        Files.copy(
            hostsFileWindows,
            tempDir.resolve("testFileWatcherClearsCache"),
            StandardCopyOption.REPLACE_EXISTING);
    Files.setLastModifiedTime(tempHosts, FileTime.fromMillis(0));
    HostsFileParser hostsFileParser = new HostsFileParser(tempHosts);
    Clock clock = mock(Clock.class);
    hostsFileParser.setClock(clock);
    Instant now = Clock.systemUTC().instant();
    when(clock.instant()).thenReturn(now);
    assertEquals(0, hostsFileParser.cacheSize());
    assertEquals(
        kubernetesAddress,
        hostsFileParser
            .getAddressForHost(kubernetesName, Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
    assertTrue(hostsFileParser.cacheSize() > 1, "Cache must not be empty");
    Name testName = Name.fromConstantString("testFileChangeClearsCache.");
    try (BufferedWriter w =
        Files.newBufferedWriter(tempHosts, StandardCharsets.UTF_8, StandardOpenOption.APPEND)) {
      w.append("127.0.0.1  ").append(testName.toString());
      w.newLine();
    }

    Files.setLastModifiedTime(tempHosts, FileTime.fromMillis(10_0000));
    when(clock.instant()).thenReturn(now.plus(Duration.ofMinutes(6)));
    assertEquals(
        InetAddress.getByAddress(testName.toString(), localhostBytes),
        hostsFileParser
            .getAddressForHost(testName, Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
  }

  @Test
  void testInvalidContentIsIgnored() throws IOException {
    HostsFileParser hostsFileParser = new HostsFileParser(hostsFileInvalid);
    assertEquals(
        InetAddress.getByAddress("localhost", localhostBytes),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("localhost."), Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
    assertEquals(
        InetAddress.getByAddress("localalias", localhostBytes),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("localalias."), Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
    assertEquals(
        Optional.empty(),
        hostsFileParser.getAddressForHost(Name.fromConstantString("some-junk."), Type.A));
    assertNotEquals(
        Optional.empty(),
        hostsFileParser.getAddressForHost(Name.fromConstantString("example.org."), Type.A));
  }

  @Test
  void testBigFileIsNotCompletelyCachedA() throws IOException {
    HostsFileParser hostsFileParser = generateLargeHostsFile("testBigFileIsNotCompletelyCachedA");
    hostsFileParser
        .getAddressForHost(Name.fromConstantString("localhost-10."), Type.A)
        .orElseThrow(() -> new IllegalStateException("Host entry not found"));
    assertEquals(1, hostsFileParser.cacheSize());
  }

  @Test
  void testBigFileCompletelyCachedA() throws IOException {
    try {
      System.setProperty("dnsjava.hostsfile.max_size_bytes", 1024 * 1024 * 1024 + "");
      HostsFileParser hostsFileParser = generateLargeHostsFile("testBigFileCompletelyCachedA");
      hostsFileParser
          .getAddressForHost(Name.fromConstantString("localhost-10."), Type.A)
          .orElseThrow(() -> new IllegalStateException("Host entry not found"));
      assertEquals(1280, hostsFileParser.cacheSize());
    } finally {
      System.clearProperty("dnsjava.hostsfile.max_size_bytes");
    }
  }

  @Test
  void testBigFileIsNotCompletelyCachedAAAA() throws IOException {
    HostsFileParser hostsFileParser =
        generateLargeHostsFile("testBigFileIsNotCompletelyCachedAAAA");
    hostsFileParser
        .getAddressForHost(Name.fromConstantString("localhost-10."), Type.AAAA)
        .orElseThrow(() -> new IllegalStateException("Host entry not found"));
    assertEquals(1, hostsFileParser.cacheSize());
  }

  private HostsFileParser generateLargeHostsFile(String name) throws IOException {
    Path generatedLargeFile = tempDir.resolve(name);
    try (BufferedWriter w = Files.newBufferedWriter(generatedLargeFile)) {
      for (int i = 0; i < 1024; i++) {
        w.append("127.0.0.")
            .append(String.valueOf(i))
            .append(" localhost-")
            .append(String.valueOf(i));
        w.newLine();
        w.append("::")
            .append(Integer.toHexString(i))
            .append(" localhost-")
            .append(String.valueOf(i));
        w.newLine();
      }
    }
    return new HostsFileParser(generatedLargeFile);
  }

  @Test
  void testBigFileNotFoundA() throws IOException {
    HostsFileParser hostsFileParser = generateLargeHostsFile("testBigFileNotFoundA");
    hostsFileParser
        .getAddressForHost(Name.fromConstantString("localhost-1024."), Type.A)
        .ifPresent(
            entry -> {
              throw new IllegalStateException("Host entry not found");
            });
    assertEquals(0, hostsFileParser.cacheSize());
  }

  @Test
  void testBigFileNotFoundAAAA() throws IOException {
    HostsFileParser hostsFileParser = generateLargeHostsFile("testBigFileNotFoundAAAA");
    hostsFileParser
        .getAddressForHost(Name.fromConstantString("localhost-1024."), Type.AAAA)
        .ifPresent(
            entry -> {
              throw new IllegalStateException("Host entry not found");
            });
    assertEquals(0, hostsFileParser.cacheSize());
  }

  @Test
  void testDualStackLookup() throws IOException {
    HostsFileParser hostsFileParser = new HostsFileParser(hostsFileInvalid);
    assertEquals(
        InetAddress.getByAddress("localhost", localhostBytes),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("localhost."), Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
    byte[] ipv6Localhost = new byte[16];
    ipv6Localhost[15] = 1;
    assertEquals(
        InetAddress.getByAddress("localhost", ipv6Localhost),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("localhost."), Type.AAAA)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
  }

  @Test
  void testDuplicateItemReturnsFirst() throws IOException {
    HostsFileParser hostsFileParser = new HostsFileParser(hostsFileInvalid);
    assertEquals(
        InetAddress.getByAddress("example.com", new byte[] {127, 0, 0, 5}),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("example.com."), Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));

    // lookup a second time to validate the cache entry
    assertEquals(
        InetAddress.getByAddress("example.com", new byte[] {127, 0, 0, 5}),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("example.com."), Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
  }

  @Test
  void testDuplicateItemReturnsFirstOnLargeFile() throws IOException {
    Path generatedLargeFile = tempDir.resolve("testDuplicateItemReturnsFirstOnLargeFile");
    try (BufferedWriter w = Files.newBufferedWriter(generatedLargeFile)) {
      for (int i = 1; i < 1024; i++) {
        w.append("127.0.0.").append(String.valueOf(i)).append(" localhost");
        w.newLine();
      }
    }
    HostsFileParser hostsFileParser = new HostsFileParser(generatedLargeFile);
    assertEquals(
        InetAddress.getByAddress("localhost", new byte[] {127, 0, 0, 1}),
        hostsFileParser
            .getAddressForHost(Name.fromConstantString("localhost."), Type.A)
            .orElseThrow(() -> new IllegalStateException("Host entry not found")));
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.hosts;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Address;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * Parses and caches the system's local hosts database, otherwise known as {@code /etc/hosts}. The
 * cache is cleared when the file is modified.
 *
 * @since 3.4
 */
@Slf4j
public final class HostsFileParser {
  private final int maxFullCacheFileSizeBytes =
      Integer.parseInt(System.getProperty("dnsjava.hostsfile.max_size_bytes", "16384"));
  private final Duration fileChangeCheckInterval =
      Duration.ofMillis(
          Integer.parseInt(
              System.getProperty("dnsjava.hostsfile.change_check_interval_ms", "300000")));

  private final Path path;
  private final boolean clearCacheOnChange;
  private Clock clock = Clock.systemUTC();

  @SuppressWarnings("java:S3077")
  private volatile Map<String, InetAddress> hostsCache;

  private Instant lastFileModificationCheckTime = null;
  private Instant lastFileReadTime = null;
  private boolean isEntireFileParsed;
  private boolean hostsFileWarningLogged = false;
  private long hostsFileSizeBytes;

  /**
   * Creates a new instance based on the current OS's default. Unix and alike (or rather everything
   * else than Windows) use {@code /etc/hosts}, while on Windows {@code
   * %SystemRoot%\System32\drivers\etc\hosts} is used. The cache is cleared when the file has
   * changed.
   */
  public HostsFileParser() {
    this(
        System.getProperty("os.name").contains("Windows")
            ? Paths.get(System.getenv("SystemRoot"), "\\System32\\drivers\\etc\\hosts")
            : Paths.get("/etc/hosts"),
        true);
  }

  /**
   * Creates an instance with a custom hosts database path. The cache is cleared when the file has
   * changed.
   *
   * @param path The path to the hosts database.
   */
  public HostsFileParser(Path path) {
    this(path, true);
  }

  /**
   * Creates an instance with a custom hosts database path.
   *
   * @param path The path to the hosts database.
   * @param clearCacheOnChange set to true to clear the cache when the hosts file changes.
   */
  public HostsFileParser(Path path, boolean clearCacheOnChange) {
    this.path = Objects.requireNonNull(path, "path is required");
    this.clearCacheOnChange = clearCacheOnChange;
    if (Files.isDirectory(path)) {
      throw new IllegalArgumentException("path must be a file");
    }
  }

  /**
   * Performs on-demand parsing and caching of the local hosts database.
   *
   * @param name the hostname to search for.
   * @param type Record type to search for, see {@link org.xbill.DNS.Type}.
   * @return The first address found for the requested hostname.
   * @throws IOException When the parsing fails.
   * @throws IllegalArgumentException when {@code type} is not {@link org.xbill.DNS.Type#A} or{@link
   *     org.xbill.DNS.Type#AAAA}.
   */
  public Optional<InetAddress> getAddressForHost(Name name, int type) throws IOException {
    Objects.requireNonNull(name, "name is required");
    if (type != Type.A && type != Type.AAAA) {
      throw new IllegalArgumentException("type can only be A or AAAA");
    }

    validateCache();

    InetAddress cachedAddress = hostsCache.get(key(name, type));
    if (cachedAddress != null) {
      return Optional.of(cachedAddress);
    }

    if (isEntireFileParsed) {
      return Optional.empty();
    }

    if (hostsFileSizeBytes > maxFullCacheFileSizeBytes) {
      searchHostsFileForEntry(name, type);
    }

    return Optional.ofNullable(hostsCache.get(key(name, type)));
  }

  private void parseEntireHostsFile() throws IOException {
    String line;
    int lineNumber = 0;
    AtomicInteger addressFailures = new AtomicInteger(0);
    AtomicInteger nameFailures = new AtomicInteger(0);
    try (BufferedReader hostsReader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      while ((line = hostsReader.readLine()) != null) {
        LineData lineData = parseLine(++lineNumber, line, addressFailures, nameFailures);
        if (lineData != null) {
          for (Name lineName : lineData.names) {
            InetAddress lineAddress =
                InetAddress.getByAddress(lineName.toString(true), lineData.address);
            hostsCache.putIfAbsent(key(lineName, lineData.type), lineAddress);
          }
        }
      }
    }

    if (!hostsFileWarningLogged && (addressFailures.get() > 0 || nameFailures.get() > 0)) {
      log.warn(
          "Failed to parse entire hosts file {}, address failures={}, name failures={}",
          path,
          addressFailures.get(),
          nameFailures);
      hostsFileWarningLogged = true;
    }
  }

  private void searchHostsFileForEntry(Name name, int type) throws IOException {
    String line;
    int lineNumber = 0;
    AtomicInteger addressFailures = new AtomicInteger(0);
    AtomicInteger nameFailures = new AtomicInteger(0);
    try (BufferedReader hostsReader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      while ((line = hostsReader.readLine()) != null) {
        LineData lineData = parseLine(++lineNumber, line, addressFailures, nameFailures);
        if (lineData != null) {
          for (Name lineName : lineData.names) {
            boolean isSearchedEntry = lineName.equals(name);
            if (isSearchedEntry && type == lineData.type) {
              InetAddress lineAddress =
                  InetAddress.getByAddress(lineName.toString(true), lineData.address);
              hostsCache.putIfAbsent(key(lineName, lineData.type), lineAddress);
              return;
            }
          }
        }
      }
    }

    if (!hostsFileWarningLogged && (addressFailures.get() > 0 || nameFailures.get() > 0)) {
      log.warn(
          "Failed to find {} in hosts file {}, address failures={}, name failures={}",
          name,
          path,
          addressFailures.get(),
          nameFailures);
      hostsFileWarningLogged = true;
    }
  }

  @RequiredArgsConstructor
  private static final class LineData {
    final int type;
    final byte[] address;
    final Iterable<? extends Name> names;
  }

  private LineData parseLine(
      int lineNumber, String line, AtomicInteger addressFailures, AtomicInteger nameFailures) {
    String[] lineTokens = getLineTokens(line);
    if (lineTokens.length < 2) {
      return null;
    }

    int lineAddressType = Type.A;
    byte[] lineAddressBytes = Address.toByteArray(lineTokens[0], Address.IPv4);
    if (lineAddressBytes == null) {
      lineAddressBytes = Address.toByteArray(lineTokens[0], Address.IPv6);
      lineAddressType = Type.AAAA;
    }

    if (lineAddressBytes == null) {
      log.debug("Could not decode address {}, {}#L{}", lineTokens[0], path, lineNumber);
      addressFailures.incrementAndGet();
      return null;
    }

    Iterable<? extends Name> lineNames =
        Arrays.stream(lineTokens)
                .skip(1)
                .map(lineTokenName -> safeName(lineTokenName, lineNumber, nameFailures))
                .filter(Objects::nonNull)
            ::iterator;
    return new LineData(lineAddressType, lineAddressBytes, lineNames);
  }

  private Name safeName(String name, int lineNumber, AtomicInteger nameFailures) {
    try {
      return Name.fromString(name, Name.root);
    } catch (TextParseException e) {
      log.debug("Could not decode name {}, {}#L{}, skipping", name, path, lineNumber);
      nameFailures.incrementAndGet();
      return null;
    }
  }

  private String[] getLineTokens(String line) {
    // everything after a # until the end of the line is a comment
    int commentStart = line.indexOf('#');
    if (commentStart == -1) {
      commentStart = line.length();
    }

    return line.substring(0, commentStart).trim().split("\\s+");
  }

  private void validateCache() throws IOException {
    if (!clearCacheOnChange) {
      if (hostsCache == null) {
        synchronized (this) {
          if (hostsCache == null) {
            readHostsFile();
          }
        }
      }

      return;
    }

    if (hostsCache == null
        || lastFileModificationCheckTime == null
        || lastFileModificationCheckTime.plus(fileChangeCheckInterval).isBefore(clock.instant())) {
      log.debug("Checked for changes more than 5minutes ago, checking");
      // A filewatcher / inotify etc. would be nicer, but doesn't work. c.f. the write up at
      // https://blog.arkey.fr/2019/09/13/watchservice-and-bind-mount/

      synchronized (this) {
        if (hostsCache != null
            && lastFileModificationCheckTime != null
            && !lastFileModificationCheckTime
                .plus(fileChangeCheckInterval)
                .isBefore(clock.instant())) {
          log.debug("Never mind, check fulfilled in another thread");
          return;
        }

        lastFileModificationCheckTime = clock.instant();
        readHostsFile();
      }
    }
  }

  private void readHostsFile() throws IOException {
    if (Files.exists(path)) {
      Instant fileTime = Files.getLastModifiedTime(path).toInstant();
      if (lastFileReadTime == null || !lastFileReadTime.equals(fileTime)) {
        createOrClearCache();

        hostsFileSizeBytes = Files.size(path);
        if (hostsFileSizeBytes <= maxFullCacheFileSizeBytes) {
          parseEntireHostsFile();
          isEntireFileParsed = true;
        }

        lastFileReadTime = fileTime;
      }
    } else {
      createOrClearCache();
    }
  }

  private void createOrClearCache() {
    if (hostsCache == null) {
      hostsCache = new ConcurrentHashMap<>();
    } else {
      hostsCache.clear();
    }
  }

  private String key(Name name, int type) {
    return name.toString() + '\t' + type;
  }

  // for unit testing only
  int cacheSize() {
    return hostsCache == null ? 0 : hostsCache.size();
  }

  void setClock(Clock clock) {
    this.clock = clock;
  }
}

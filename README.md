[![dnsjava CI](https://github.com/dnsjava/dnsjava/actions/workflows/build.yml/badge.svg)](https://github.com/dnsjava/dnsjava/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/dnsjava/dnsjava/branch/master/graph/badge.svg?token=FKmcwl1Oys)](https://codecov.io/gh/dnsjava/dnsjava)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/dnsjava/dnsjava/badge.svg)](https://search.maven.org/artifact/dnsjava/dnsjava)
[![Javadocs](http://javadoc.io/badge/dnsjava/dnsjava.svg)](http://javadoc.io/doc/dnsjava/dnsjava)

# dnsjava

## Overview

dnsjava is an implementation of DNS in Java. It supports almost all defined record
types (including the DNSSEC types), and unknown types. It can be used for
queries, zone transfers, and dynamic updates. It includes a cache which can be
used by clients, and an authoritative only server. It supports TSIG
authenticated messages, partial DNSSEC verification, and EDNS0. It is fully
thread safe.

dnsjava was started as an excuse to learn Java. It was useful for testing new
features in BIND without rewriting the C resolver. It was then cleaned up and
extended in order to be used as a testing framework for DNS interoperability
testing. The high level API and caching resolver were added to make it useful
to a wider audience. The authoritative only server was added as proof of
concept.

## dnsjava on Github

This repository has been a mirror of the dnsjava project at Sourceforge
since 2014 to maintain the Maven build for publishing to
[Maven Central](https://search.maven.org/artifact/dnsjava/dnsjava).
As of 2019-05-15, Github is
[officially](https://sourceforge.net/p/dnsjava/mailman/message/36666800/)
the new home of dnsjava.

Please use the Github [issue tracker](https://github.com/dnsjava/dnsjava/issues)
and send - well tested - pull requests. The
[dnsjava-users@lists.sourceforge.net](mailto:dnsjava-users@lists.sourceforge.net)
mailing list still exists.

## Getting started

### Config options
Some settings of dnsjava can be configured via
[system properties](https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html):

<table>
    <thead>
        <tr>
            <th rowspan="2">Property</th>
            <th>Type</th>
            <th>Default</th>
            <th>Example</th>
        </tr>
        <tr>
            <th colspan="3">Explanation</th>
        </tr>
    </thead>
    <tbody class="rich-diff-level-one">
        <tr>
            <td rowspan="2">dns[.fallback].server</td>
            <td>String</td>
            <td>-</td>
            <td>8.8.8.8,[2001:4860:4860::8888]:853,dns.google</td>
        </tr>
        <tr>
            <td colspan="3">DNS server(s) to use for resolving. Comma separated list. Can be IPv4/IPv6 addresses or hostnames (which are resolved using Java's built in DNS support).</td>
        </tr>
        <tr>
            <td rowspan="2">dns[.fallback].search</td>
            <td>String</td>
            <td>-</td>
            <td>ds.example.com,example.com</td>
        </tr>
        <tr>
            <td colspan="3">Comma separated list of DNS search paths.</td>
        </tr>
        <tr>
            <td rowspan="2">dns[.fallback].ndots</td>
            <td>Integer</td>
            <td>1</td>
            <td>2</td>
        </tr>
        <tr>
            <td colspan="3">Sets a threshold for the number of dots which must appear in a name given to resolve before an initial absolute query will be made.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.options</td>
            <td>option list</td>
            <td>-</td>
            <td>BINDTTL,tsigfudge=1</td>
        </tr>
        <tr>
            <td colspan="3">Comma separated key-value pairs, see below.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.configprovider.skipinit</td>
            <td>Boolean</td>
            <td>false</td>
            <td>true</td>
        </tr>
        <tr>
            <td colspan="3">Set to true to disable static ResolverConfig initialization.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.configprovider.sunjvm.enabled</td>
            <td>Boolean</td>
            <td>false</td>
            <td>true</td>
        </tr>
        <tr>
            <td colspan="3">Set to true to enable the reflection based DNS server lookup, see limitations below.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.udp.ephemeral.start</td>
            <td>Integer</td>
            <td>49152 (Linux: 32768)</td>
            <td>50000</td>
        </tr>
        <tr>
            <td colspan="3">First ephemeral port for UDP-based DNS queries.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.udp.ephemeral.end</td>
            <td>Integer</td>
            <td>65535 (Linux: 60999)</td>
            <td>60000</td>
        </tr>
        <tr>
            <td colspan="3">Last ephemeral port for UDP-based DNS queries.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.udp.ephemeral.use_ephemeral_port</td>
            <td>Boolean</td>
            <td>false</td>
            <td>true</td>
        </tr>
        <tr>
            <td colspan="3">Use an OS-assigned ephemeral port for UDP queries. Enabling this option is insecure! Do NOT use it.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.lookup.max_iterations</td>
            <td>Integer</td>
            <td>16</td>
            <td>20</td>
        </tr>
        <tr>
            <td colspan="3">Maximum number of CNAMEs to follow in a chain.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.lookup.use_hosts_file</td>
            <td>Boolean</td>
            <td>true</td>
            <td>false</td>
        </tr>
        <tr>
            <td colspan="3">Use the system's hosts file for lookups before resorting to a resolver.</td>
        </tr>
        <tr>
            <td rowspan="2">dnsjava.disable_idn</td>
            <td>Boolean</td>
            <td>false</td>
            <td>true</td>
        </tr>
        <tr>
            <td colspan="3">Disable parsing of Internationalized Domain Names (IDN).</td>
        </tr>
    </tbody>
</table>

#### dnsjava.options pairs
The dnsjava.options configuration options can also be set programmatically
through the `Options` class. Please refer to the Javadoc for details.

| Key | Type | Default | Explanation |
| --- | ---- | -------|  ----------- |
| BINDTTL | Boolean | false | Print TTLs in BIND format |
| multiline | Boolean | false | Print records in multiline format |
| noPrintIN | Boolean | false | Do not print the class of a record if it is `IN` |
| tsigfudge | Integer | 300 | Sets the default TSIG fudge value (in seconds) |
| sig0validity | Integer | 300 | Sets the default SIG(0) validity period (in seconds) |

### Resolvers
dnsjava comes with several built-in resolvers: 
- `SimpleResolver`: a basic resolver that uses UDP by default and falls back
  to TCP if required.
- `ExtendedResolver`: a resolver that uses multiple `SimpleResolver`s to send
   the queries. Can be configured to query the servers in a round-robin order.
   Blacklists a server if it times out.
- `DohResolver`: a proof-of-concept DNS over HTTP resolver, e.g. to use
  `https://dns.google/query`.

The project [dnssecjava](https://github.com/ibauersachs/dnssecjava) has a
resolver that validates responses with DNSSEC.

### Migrating from version 2.1.x to v3
dnsjava 3 has significant API changes compared to version 2.1.x and is
neither source nor binary compatible. The most important changes are:
- The minimum supported version is Java 8
- Uses [slf4j](http://www.slf4j.org/) for logging and thus needs `slf4j-api`
  on the classpath
- The [command line tools](USAGE.md) were moved to the `org.xbill.DNS.tools`
  package
- On Windows, [JNA](https://github.com/java-native-access/jna) should be
  on the classpath for the search path
- The `Resolver` API for custom resolvers has changed to use
  `CompletionStage<Message>` for asynchronous resolving. The built-in
   resolvers are now fully non-blocking and do not start a thread per
   query anymore.
- Many methods return a `List<T>` instead of an array. Ideally, use a
  for-each loop. If this isn't possible, call `size()` instead of
  using `length`:
  - Cache#findAnyRecords
  - Cache#findRecords
  - Lookup#getDefaultSearchPath
  - Message#getSectionRRsets
  - SetResponse#answers
  - ResolverConfig
- RRset returns a List<T> instead of an `Iterator`. Ideally, modify your
  code to use a for-each loop. If this is not possible, create an iterator
  on the returned list:
  - RRset#rrs
  - RRset#sigs
- Methods using `java.util.Date` are deprecated. Use the new versions with
  `java.time.Instant` or `java.time.Duration` instead
- The type hierarchy of `SMIMEARecord` changed, it now inherits from
  `TLSARecord` and constants are shared
- `Record`s are no longer marked as `Serializable`. Use the RFC defined
   serialization formats:
   - `toString()`, `rrToString()` <-> `fromString()`
   - `toWire()` <-> `fromWire()`, `newRecord()`
- `Message` and `Header` properly support `clone()`

### Replacing the standard Java DNS functionality

Java versions from 1.4 to 8 can load DNS service providers at runtime. The
functionality was [removed in JDK 9](https://bugs.openjdk.java.net/browse/JDK-8134577),
a replacement is [requested](https://bugs.openjdk.java.net/browse/JDK-8192780),
but so far only a [proposal](https://bugs.openjdk.java.net/browse/JDK-8263693)
has been defined.

To load the dnsjava service provider, build dnsjava on JDK 8 and set the system property:

	sun.net.spi.nameservice.provider.1=dns,dnsjava

This instructs the JVM to use the dnsjava service provide for DNS at the
highest priority.

### Build

Run `mvn package` from the toplevel directory to build dnsjava. JDK 8
or higher is required.

### Testing dnsjava

[Matt Rutherford](mailto:rutherfo@cs.colorado.edu) contributed a number of unit
tests, which are in the tests subdirectory. The hierarchy under tests
mirrors the org.xbill.DNS classes. To run the unit tests, execute
`mvn test`.


## Limitations

There's no standard way to determine what the local nameserver or DNS search
path is at runtime from within the JVM. dnsjava attempts several methods
until one succeeds.

- The properties `dns.server` and `dns.search` (comma delimited lists) are
  checked. The servers can either be IP addresses or hostnames (which are
  resolved using Java's built in DNS support).
- On Unix/Solaris, `/etc/resolv.conf` is parsed.
- On Windows, if [JNA](https://github.com/java-native-access/jna) is available
  on the classpath, the `GetAdaptersAddresses` API is used.
- On Android the `ConnectivityManager` is used (requires initialization using
  `org.xbill.DNS.config.AndroidResolverConfigProvider.setContext`).
- The `sun.net.dns.ResolverConfiguration` class is queried if enabled. As of
  Java 16 the JVM flag `--add-opens java.base/sun.net.dns=ALL-UNNAMED` is also
  required.
- If available and no servers have been found yet,
  [JNDI-DNS](https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-dns.html) is used.
- If still no servers have been found yet, use the fallback properties. This can be used to query
  e.g. a well-known public DNS server instead of localhost. 
- As a last resort, `localhost` is used as the nameserver, and the search
  path is empty.


## Additional documentation

Javadoc documentation can be built with `mvn javadoc:javadoc` or viewed online
at [javadoc.io](http://javadoc.io/doc/dnsjava/dnsjava). See the
[examples](EXAMPLES.md) for some basic usage information.


## License

dnsjava is placed under the [BSD-3-Clause license](LICENSE).

## Authors

- Brian Wellington (@bwelling), March 12, 2004
- Various contributors, see [Changelog](Changelog)
- Ingo Bauersachs (@ibauersachs), current maintainer

## Final notes
- Thanks to Network Associates, Inc. for sponsoring some of the original
  dnsjava work in 1999-2000.
- Thanks to Nominum, Inc. for sponsoring some work on dnsjava from 2000 through 2017.

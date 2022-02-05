= dnsjava

image:https://github.com/dnsjava/dnsjava/actions/workflows/build.yml/badge.svg["GitHub CI Build Status",link="https://github.com/dnsjava/dnsjava/actions/workflows/build.yml"]
image:https://codecov.io/gh/dnsjava/dnsjava/branch/master/graph/badge.svg?token=FKmcwl1Oys["codecov",link="https://codecov.io/gh/dnsjava/dnsjava"]
image:https://maven-badges.herokuapp.com/maven-central/dnsjava/dnsjava/badge.svg["Maven Central",link="https://search.maven.org/artifact/dnsjava/dnsjava"]
image:https://javadoc.io/badge/dnsjava/dnsjava.svg["Javadocs",link="https://javadoc.io/doc/dnsjava/dnsjava"]

== Overview

dnsjava is an implementation of DNS in Java.
It

* supports almost all defined record types (including the DNSSEC types), and unknown types.
* can be used for queries, zone transfers, and dynamic updates.
* includes a cache which can be used by clients, and an authoritative only server.
* supports TSIG authenticated messages, DNSSEC verification, and EDNS0.
* is fully thread safe.

== Getting started
Have a look at the basic link:EXAMPLES.md[examples].

=== Config options

Some settings of dnsjava can be configured via Java
https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html[system properties]:

[cols=4*]
|===
.2+h|Property
3+h|Explanation
h|Type
h|Default
h|Example

.2+|dns[.fallback].server
3+|DNS server(s) to use for resolving.
Comma separated list.
Can be IPv4/IPv6 addresses or hostnames (which are resolved using Java's built in DNS support).
|String
|-
|8.8.8.8,[2001:4860:4860::8888]:853,dns.google

.2+|dns[.fallback].search
3+|Comma separated list of DNS search paths.
|String
|-
|ds.example.com,example.com

.2+|dns[.fallback].ndots
3+|Sets a threshold for the number of dots which must appear in a name given to resolve before an initial absolute query will be made.
|Integer
|1
|2

.2+|dnsjava.options
3+|Comma separated key-value pairs, see <<_optionpairs>>.
|option list
|-
|BINDTTL,tsigfudge=1

.2+|dnsjava.configprovider.skipinit
3+|Set to true to disable static ResolverConfig initialization.
|Boolean
|false
|true

.2+|dnsjava.configprovider.sunjvm.enabled
3+|Set to true to enable the reflection based DNS server lookup, see <<_limitations>>.
|Boolean
|false
|true

.2+|dnsjava.udp.ephemeral.start
3+|First ephemeral port for UDP-based DNS queries.
|Integer
|49152 (Linux: 32768)
|50000

.2+|dnsjava.udp.ephemeral.end
3+|Last ephemeral port for UDP-based DNS queries.
|Integer
|65535 (Linux: 60999)
|60000

.2+|dnsjava.udp.ephemeral.use_ephemeral_port
3+|Use an OS-assigned ephemeral port for UDP queries.
Enabling this option is *insecure*!
Do NOT use it.
|Boolean
|false
|true

.2+|dnsjava.lookup.max_iterations
3+|Maximum number of CNAMEs to follow in a chain.
|Integer
|16
|20

.2+|dnsjava.lookup.use_hosts_file
3+|Use the system's hosts file for lookups before resorting to a resolver.
|Boolean
|true
|false

4+h|dnssec options
.2+|dnsjava.dnssec.keycache.max_ttl
3+|Maximum time-to-live (TTL) of entries in the key cache in seconds.
|Integer
|900
|1800

.2+|dnsjava.dnssec.keycache.max_size
3+|Maximum number of entries in the key cache.
|Integer
|1000
|5000

.2+|org.jitsi.dnssec.nsec3.iterations.N
3+a|Maximum iteration count for the NSEC3 hashing function depending on the key size N. The defaults are from https://www.rfc-editor.org/rfc/rfc5155.html#section-10.3[RFC5155].
|Integer
2+a|- 1024 bit keys: 150 iterations
- 2048 bit keys: 500 iterations
- 4096 bit keys: 2500 iterations

e.g. dnsjava.dnssec.nsec3.iterations.1024=200

.2+|dnsjava.dnssec.trust_anchor_file
3+|The file from which the trust anchor should be loaded.
The file must be formatted like a DNS zone master file.
It can only contain DS or DNSKEY records.
|String
|-
|/etc/dnssec-root-anchors

.2+|dnsjava.dnssec.digest_preference
3+|Defines the preferred DS record digest algorithm if a zone has registered multiple DS records.
The list is comma-separated, the highest preference first.

If this property is not specified, the DS record with the highest
https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml[digest ID] is chosen.
To stay compliant with the RFCs, the mandatory digest IDs must be listed in this property.

The GOST digest requires https://www.bouncycastle.org/java.html[BouncyCastle] on the classpath.
|String
|-
|2,1,4

.2+|dnsjava.dnssec.harden_algo_downgrade
3+|Prevent algorithm downgrade when multiple algorithms are advertised in a zone's DS records.
If `false`, allows any algorithm to validate the zone.
|Boolean
|true
|false

.2+|dnsjava.dnssec.algorithm_enabled.ID
3+|Enable or disable a DS/DNSKEY algorithm.
See
https://www.rfc-editor.org/rfc/rfc8624.html#section-3.1[RFC8624] for recommended values.
|Boolean
2+|Disable ED448:
`dnsjava.dnssec.algorithm_enabled.16=false`

.2+|dnsjava.dnssec.digest_enabled.ID
3+|Enable or disable a DS record digest algorithm.
See
https://www.rfc-editor.org/rfc/rfc8624.html#section-3.3[RFC8624] for recommended values.
|Boolean
2+|Disable SHA.1:
`dnsjava.dnssec.digest_enabled.1=false`

|===

[#_optionpairs]
==== dnsjava.options pairs

The `dnsjava.options` configuration options can also be set programmatically through the `Options` class.
Please refer to the Javadoc for details.

[cols="1,1,1,4",options=header]
|===
| Key | Type | Default | Explanation
| `BINDTTL` | Boolean | false | Print TTLs in BIND format
| `multiline` | Boolean | false | Print records in multiline format
| `noPrintIN` | Boolean | false | Do not print the class of a record if it is `IN`
| `tsigfudge` | Integer | 300 | Sets the default TSIG fudge value (in seconds)
| `sig0validity` | Integer | 300 | Sets the default SIG(0) validity period (in seconds)
|===

=== Resolvers

==== SimpleResolver

Basic resolver that uses UDP by default and falls back to TCP if required.

==== ExtendedResolver

Resolver that uses multiple ``SimpleResolver``s to send the queries.
Can be configured to query the servers in a round-robin order.
Blacklists a server if it times out.

==== DohResolver

Proof-of-concept DNS over HTTP resolver, e.g. to use https://dns.google/query.

==== ValidatingResolver

DNSSEC validating stub resolver.
Originally based on the work of the Unbound Java prototype from 2005/2006.
The Unbound prototype was stripped from all unnecessary parts, heavily modified, complemented with more than 300 unit test and found bugs were fixed.
Before the import into dnsjava, the resolver was developed as an independent library at https://github.com/ibauersachs/dnssecjava.
To migrate from dnssecjava, replace `org.jitsi` with `org.xbill.DNS` in Java packages and `org.jitsi` with `dnsjava` in property prefixes.

Validated, secure responses contain the DNS `AD`-flag, while responses that failed validation return the `SERVFAIL`-RCode.
Insecure responses return the actual return code without the `AD`-flag set.
The reason why the validation failed or is insecure is provided as a localized string in the additional section under the record ./65280/TXT (a TXT record for the owner name of the root zone in the private query class `ValidatingResolver.VALIDATION_REASON_QCLASS`).
The Extended DNS Errors (EDE, https://www.rfc-editor.org/rfc/rfc8914.html[RFC8914]) also provides the failure reason, although in less detail.

The link:EXAMPLES.md[examples] contain a small demo.

=== Migrating from version 2.1.x to v3

dnsjava v3 has significant API changes compared to version 2.1.x and is neither source nor binary compatible.
The most important changes are:

* Requires at least Java 8

* Uses http://www.slf4j.org/[slf4j] for logging and thus needs `slf4j-api`
on the classpath

* The link:USAGE.md[command line tools] were moved to the `org.xbill.DNS.tools`
package

* On Windows, https://github.com/java-native-access/jna[JNA] should be on the classpath for the search path and proper DNS server finding

* The `Resolver` API for custom resolvers has changed to use
`CompletionStage<Message>` for asynchronous resolving.
The built-in resolvers are now fully non-blocking and do not start a thread per query anymore.

* Many methods return a `List<T>` instead of an array.
Ideally, use a for-each loop.
If this is not possible, call `size()` instead of using `length`:
** Cache#findAnyRecords
** Cache#findRecords
** Lookup#getDefaultSearchPath
** Message#getSectionRRsets
** SetResponse#answers
** ResolverConfig

* RRset returns a List<T> instead of an `Iterator`.
Ideally, modify your code to use a for-each loop.
If this is not possible, create an iterator on the returned list:
** RRset#rrs
** RRset#sigs

* Methods using `java.util.Date` are deprecated.
Use the new versions with
`java.time.Instant` or `java.time.Duration` instead

* The type hierarchy of `SMIMEARecord` changed, it now inherits from
`TLSARecord` and constants are shared

* ``Record``s are no longer marked as `Serializable` after 3.0.
While 3.5 reintroduced `Serializable`, it is preferred to use the RFC defined serialization formats directly:
** `toString()`, `rrToString()` ↔ `fromString()`
** `toWire()` ↔ `fromWire()`, `newRecord()`

* `Message` and `Header` properly support `clone()`

=== Replacing the standard Java DNS functionality

==== Java 1.4 to 8

Java versions from 1.4 to 8 can load DNS service providers at runtime.
To load the dnsjava service provider, build dnsjava on JDK 8 and set the system property:

	sun.net.spi.nameservice.provider.1=dns,dnsjava

This instructs the JVM to use the dnsjava service provide for DNS at the highest priority.

==== Java 9 to 17

The functionality to load a DNS SPI was https://bugs.openjdk.java.net/browse/JDK-8134577[removed in JDK 9] and a replacement API was https://bugs.openjdk.java.net/browse/JDK-8192780[requested].

==== Java 18+

https://bugs.openjdk.java.net/browse/JDK-8263693[JEP 418: Internet-Address Resolution SPI] reintroduces a DNS SPI.
See https://github.com/dnsjava/dnsjava/issues/245[#245] for the support status in dnsjava.

=== Build

dnsjava uses https://maven.apache.org/[Maven] as the build system.
Run `mvn package` from the toplevel directory to build dnsjava.
JDK 8 or higher is required.

=== Testing dnsjava

mailto:rutherfo@cs.colorado.edu[Matt Rutherford] contributed a number of unit tests, which are in the tests subdirectory.

The hierarchy under tests mirrors the `org.xbill.DNS` classes.
To run the unit tests, execute `mvn test`.

[#_limitations]
== Limitations

There is no standard way to determine what the local nameserver or DNS search path is at runtime from within the JVM.
dnsjava attempts several methods until one succeeds.

- The properties `dns.server` and `dns.search` (comma delimited lists) are checked.
The servers can either be IP addresses or hostnames (which are resolved using Java's built in DNS support).
- On Unix/Solaris, `/etc/resolv.conf` is parsed.
- On Windows, if https://github.com/java-native-access/jna[JNA] is available on the classpath, the `GetAdaptersAddresses` API is used.
- On Android the `ConnectivityManager` is used (requires initialization using `org.xbill.DNS.config.AndroidResolverConfigProvider.setContext`).
- The `sun.net.dns.ResolverConfiguration` class is queried if enabled.
As of Java 16 the JVM flag `--add-opens java.base/sun.net.dns=ALL-UNNAMED` is also required.
- If available and no servers have been found yet, https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-dns.html[JNDI-DNS] is used.
- If still no servers have been found yet, use the fallback properties.
This can be used to query e.g. a well-known public DNS server instead of localhost.
- As a last resort, `localhost` is used as the nameserver, and the search path is empty.

== Additional documentation

Javadoc documentation can be built with `mvn javadoc:javadoc` or viewed online at https://javadoc.io/doc/dnsjava/dnsjava[javadoc.io].
See the link:EXAMPLES.md[examples] for some basic usage information.

== License

dnsjava is placed under the link:LICENSE[BSD-3-Clause license].

== History

dnsjava was started as an excuse to learn Java.
It was useful for testing new features in BIND without rewriting the C resolver.
It was then cleaned up and extended in order to be used as a testing framework for DNS interoperability testing.
The high level API and caching resolver were added to make it useful to a wider audience.
The authoritative only server was added as proof of concept.

=== dnsjava on GitHub

This repository has been a mirror of the dnsjava project at Sourceforge since 2014 to maintain the Maven build for publishing to https://search.maven.org/artifact/dnsjava/dnsjava[Maven Central].
As of 2019-05-15, GitHub is https://sourceforge.net/p/dnsjava/mailman/message/36666800/[officially] the new home of dnsjava.
The mailto:dnsjava-users@lists.sourceforge.net[dnsjava-users] mailing list (https://sourceforge.net/p/dnsjava/mailman/dnsjava-users/[archive]) still exists but is mostly inactive.

Please use the GitHub https://github.com/dnsjava/dnsjava/issues[issue tracker] and send - well tested - pull requests.

== Authors

- Brian Wellington (@bwelling), March 12, 2004
- Various contributors, see the link:Changelog[Changelog]
- Ingo Bauersachs (@ibauersachs), current maintainer

== Final notes

- Thanks to Network Associates, Inc. for sponsoring some of the original dnsjava work in 1999-2000.
- Thanks to Nominum, Inc. for sponsoring some work on dnsjava from 2000 through 2017.

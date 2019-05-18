[![Build Status](https://travis-ci.org/dnsjava/dnsjava.svg?branch=master)](https://travis-ci.org/dnsjava/dnsjava)
[![Coverage Status](https://coveralls.io/repos/dnsjava/dnsjava/badge.svg)](https://coveralls.io/r/dnsjava/dnsjava)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/dnsjava/dnsjava/badge.svg)](https://search.maven.org/artifact/dnsjava/dnsjava)
[![Javadocs](http://javadoc.io/badge/dnsjava/dnsjava.svg)](http://javadoc.io/doc/dnsjava/dnsjava)

# dnsjava

http://www.dnsjava.org/

## Overview

dnsjava is an implementation of DNS in Java.  It supports all defined record
types (including the DNSSEC types), and unknown types.  It can be used for
queries, zone transfers, and dynamic updates.  It includes a cache which can be
used by clients, and an authoritative only server.  It supports TSIG
authenticated messages, partial DNSSEC verification, and EDNS0.  It is fully
thread safe.  It can be used to replace the native DNS support in Java.

dnsjava was started as an excuse to learn Java.  It was useful for testing new
features in BIND without rewriting the C resolver.  It was then cleaned up and
extended in order to be used as a testing framework for DNS interoperability
testing.  The high level API and caching resolver were added to make it useful
to a wider audience.  The authoritative only server was added as proof of
concept.

## dnsjava on Github

This repository has been a mirror of the dnsjava project at Sourceforge
since 2014 to maintain the Maven build for publishing to
[Maven Central](https://search.maven.org/artifact/dnsjava/dnsjava).
As of 2019-05-15, Github is
[officially](https://sourceforge.net/p/dnsjava/mailman/message/36666800/)
the new home of dnsjava.

Please use the Github [issue tracker](issues) and send - well tested - pull
requests. The dnsjav-users
[dnsjava-users@lists.sourceforge.net](mailto:dnsjava-users@lists.sourceforge.net)
still exists.

## Author

- Brian Wellington (@bwelling), March 12, 2004
- Various contributors, see [Changelog](Changelog)

## Getting started

Run `mvn package` from the toplevel directory to build dnsjava. JDK 1.4
or higher is required.

### Replacing the standard Java DNS functionality:

Java versions from 1.4 to 1.8 can load DNS service providers at runtime. The
functionality was [removed in JDK 9](https://bugs.openjdk.java.net/browse/JDK-8134577),
a replacement is [requested](https://bugs.openjdk.java.net/browse/JDK-8192780),
but so far has not been implemented.

To load the dnsjava service provider, build dnsjava on a JDK that still
supports the SPI and set the system property:

	sun.net.spi.nameservice.provider.1=dns,dnsjava

This instructs the JVM to use the dnsjava service provide for DNS at the
highest priority.


## Testing dnsjava

[Matt Rutherford](mailto:rutherfo@cs.colorado.edu) contributed a number of unit
tests, which are in the tests subdirectory.  The hierarchy under tests
mirrors the org.xbill.DNS classes.  To run the unit tests, execute
`mvn test`. The tests require JUnit.

Some high-level test programs are in `org/xbill/DNS/tests`.


## Limitations

There's no standard way to determine what the local nameserver or DNS search
path is at runtime from within the JVM.  dnsjava attempts several methods
until one succeeds.

- The properties `dns.server` and `dns.search` (comma delimited lists) are
  checked.  The servers can either be IP addresses or hostnames (which are
  resolved using Java's built in DNS support).
- The `sun.net.dns.ResolverConfiguration` class is queried.
- On Unix, `/etc/resolv.conf` is parsed.
- On Windows, `ipconfig`/`winipcfg` is called and its output parsed.  This may
  fail for non-English versions on Windows.
- As a last resort, `localhost` is used as the nameserver, and the search
  path is empty.

The underlying platform must use an ASCII encoding of characters.  This means
that dnsjava will not work on OS/390, for example.


## Additional documentation

Javadoc documentation can be built with `mvn javadoc:javadoc`.


## License

dnsjava is placed under the [BSD license](LICENSE). Several files are also under
additional licenses; see the individual files for details.

## Final notes
- Thanks to Network Associates, Inc. for sponsoring some of the original
  dnsjava work in 1999-2000.
- Thanks to Nominum, Inc. for sponsoring some work on dnsjava from 2000 on.

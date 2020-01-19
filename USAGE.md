dnsjava Command Line Tools
==========================

dnsjava provides several command line programs, which are documented here.
For examples of API usage, see the [examples](EXAMPLES.md). To run them,
at least `dnsjava` and `slf4j-api` need to be on the classpath. A basic
invocation could thus look as follows:

	java -cp dnsjava.jar;slf4-api.jar org.xbill.DNS.tools.Tools [tool]

dig
---
A basic, incomplete clone of dig (as distributed with BIND)

	dig @server [-x] name type [class] [-p port] [-k name/secret] [-t] \
	[-i] [-e n] [-d]
		-x  : reverse lookup, name must be a dotted quad
		-k  : use TSIG transaction security
		-t  : use TCP by default
		-i  : ignore truncation errors
		-e n: Use EDNS level n (only 0 is defined)
		-d  : Set the DNSSEC OK bit

update
------
A dynamic update client with some extra functionality.  This can be
used either interactively or by specifying a file containing commands
to be executed. Running 'help' lists all other commands.

	update [file]

jnamed
------
A basic authoritative only (non-caching, non-recursive) server. It's
not very good, but it's also a whole lot better than it used to be.

The config file (`jnamed.conf` by default) supports the following
directives:

	primary <zonename> <masterfile>
	secondary <zonename> <IP address>
	cache <hintfile>
	key [algorithm] <name> <base 64 encoded secret>
	address <IP address>
	port <port number>

If no addresses are specified, jnamed will listen on all addresses,
using a wildcard socket. If no ports are specified, jnamed will
listen on port 53.

The following is an example:

	primary internal /etc/namedb/internal.db
	secondary xbill.org 127.0.0.1
	cache /etc/namedb/cache.db
	key xbill.org 1234
	address 127.0.0.1
	port 12345

To run:

	jnamed [config_file]

jnamed should not be used for production, and should probably
not be used for testing.  If the above documentation is not enough,
please do not ask for more, because it really should not be used.

lookup
------
A simple program that looks up records associated with names.
If no type is specified, address lookups (A) are done.

	lookup [-t type] name ...

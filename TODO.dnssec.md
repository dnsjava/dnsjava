<del>CNAME Handling
--------------
<del>The CNAME handling is terribly inefficient. A recursive nameserver is required
to deliver all intermediate results in the response to the original query. The
code however still splits up the query into each part and performs a query for
each CNAME till the end of the chain is reached.
This should be changed to follow the chain in the response of the original
query, but is not so easy because the validation only has the keys for each
original query.
A possible workaround would be to synthesize the intermediate responses from
the original query. Easy for positive responses, but for NXDOMAIN - which
NSEC(3)s are to be included...?

<del>DNAME Handling
--------------
<del>A DNAME causes validation failures during priming because the synthesized
CNAME is not considered valid. Some unit-tests are failing due to this.

API
---
- <del>Provide the final failure reason as a (localizable) string

Code Coverage / Bugs
--------------------
- The code still has some untested parts:
  - <del>Wildcard/ENT DS delegations!!!
  - ANY responses, especially wildcard expansion
  - Insecure NSEC3 NODATA responses
  - <del>Wildcard NODATA responses might pass too broad cases
  - <del>Behavior if all NSEC3s are not understandable
  - NXDOMAIN when a NSEC would prove that a wildcard exists
  - Exceptions thrown by the head resolver
  - Bogus/Insecure handling of CNAME answer to DS query
  - <del>Async calling of the validator
  - <del>Passthrough without validation if the CD flag is set
  - Various cases in dsReponseToKeForNodata
  - <del>longestCommonName
  - <del>Various NSEC NODATA cases
  - <del>Unsupported algorithm or digest ID cases
  - <del>NSEC3 iteration count configuration
  - <del>NSEC3 with unsupported hash algorithm
  - Multiple NSEC3s for a zone
  - NSEC3: proveClosestEncloser
  - NSEC3: proveNodata
  - NSEC3: proveNoDS
  - <del>Implement http://tools.ietf.org/html/rfc4509#section-3 to prevent downgrade attacks
  - <del>http://tools.ietf.org/html/rfc6840#section-4.3 (CNAME bit check)
  - http://tools.ietf.org/html/rfc6840#section-4.4 (Insecure Delegation Proofs)
  - http://tools.ietf.org/html/rfc6840#section-5.4 (Caution about Local Policy and Multiple RRSIGs)
  - <del>Refuse DNAME wildcards (RFC4597)
  - Test validating against a non-Bind9 head solver
  - Rate limit queries to be able to validate against Google's public resolvers

Unit Tests
----------
- <del>The tests currently rely on an online connection to a recursive server and
  external zones. They must be able to run offline.
- <del>Some tests will start to fail after June 9, 2013 because the signature date
  is compared against the current system time. This must be changed to take
  the test authoring time. To make this possible DNSJAVA must probably be
  changed.

DNSJAVA
-------
- <del>Fix the Maven project definition to build correctly with a local lib folder
  as it is not officially distributed on Maven central
- <del>Version 2.1.5 contains a bug in the Name constructor and needs at least
  SVN rev. 1686
- <del>Remove local-repo once 2.1.6 appears on Maven central

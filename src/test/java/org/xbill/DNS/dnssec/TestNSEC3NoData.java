// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;

class TestNSEC3NoData extends TestBase {
  @ParameterizedTest(name = "testNodataNsec3_{index}")
  @CsvSource({
    "www.nsec3.ingotronic.ch./MX,DNSSEC_BOGUS",
    // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the nsec3.ingotronic.ch.
    // then return NODATA for the following query, "proofed" by the NSEC3 from the parent
    "sub.nsec3.ingotronic.ch./A,DNSSEC_BOGUS",
    // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the sub.nsec3.ingotronic.ch.
    // then return NODATA for the following query, "proofed" by the NSEC3 from the child
    "sub.nsec3.ingotronic.ch./DS,DNSSEC_BOGUS",
    // rfc5155#section-7.2.4
    // response does not contain next closer NSEC3, thus bogus
    "a.unsigned.nsec3.ingotronic.ch./DS,NSEC_MISSING",
  })
  @AlwaysOffline
  void testNodataNsec3(String query, String ede) throws IOException {
    Message response = resolver.send(createMessage(query));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertTrue(getReason(response).startsWith("failed.nodata"));
    assertEde(ExtendedErrorCodeOption.code(ede), response);
  }

  @Test
  @AlwaysOffline
  void testNodataApexNsec3ProofInsecureDelegation() throws IOException {
    // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the nsec3.ingotronic.ch. zone
    // then return NODATA for the following query, "proofed" by the NSEC3 from the parent
    // which has the DS flag removed, effectively making the reply insecure
    Message response = resolver.send(createMessage("sub.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  @AlwaysOffline
  void testNodataApexNsec3WithSOAValid() throws IOException {
    // get NSEC3 hashed whose name is sub.nsec3.ingotronic.ch. from the nsec3.ingotronic.ch.
    // then return NODATA for the following query, "proofed" by the NSEC3 from the parent
    Message response = resolver.send(createMessage("sub.nsec3.ingotronic.ch./A"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  @AlwaysOffline
  void testNoDSProofCanExistForRoot() throws IOException {
    // ./DS can exist
    resolver.getTrustAnchors().clear();
    resolver
        .getTrustAnchors()
        .store(
            new SRRset(
                new RRset(
                    toRecord(
                        ".           300 IN  DS  16758 7 1 EC88DF5E2902FD4AB9E9C246BEEA9B822BD7BCF7"))));
    Message response = resolver.send(createMessage("./DS"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  @AlwaysOffline
  void testNodataNsec3ForDSMustNotHaveSOA() throws IOException {
    // bogus./DS cannot coexist with bogus./SOA
    resolver.getTrustAnchors().clear();
    resolver
        .getTrustAnchors()
        .store(
            new SRRset(
                new RRset(
                    toRecord(
                        "bogus.           300 IN  DS  16758 7 1 A5D56841416AB42DC39629E42D12C98B0E94232A"))));
    Message response = resolver.send(createMessage("bogus./DS"));
    assertTrue(response.getHeader().getFlag(Flags.AD), "AD flag must be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }

  @Test
  @AlwaysOffline
  void testNsec3ClosestEncloserIsInsecureDelegation() throws IOException {
    Message response = resolver.send(createMessage("a.unsigned.nsec3.ingotronic.ch./A"));
    assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertNull(getReason(response));
    assertEde(-1, response);
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.PrepareMocks;
import org.xbill.DNS.dnssec.TestBase;

class TestNsec3ValUtilsPublicKeyLoading extends TestBase {
  @Test
  @PrepareMocks("prepareTestPublicKeyLoadingException")
  void testPublicKeyLoadingException() throws Exception {
    try {
      resolver.setTimeout(Duration.ofDays(1));
      Message response = resolver.send(createMessage("www.wc.nsec3.ingotronic.ch./A"));
      assertFalse(response.getHeader().getFlag(Flags.AD), "AD flag must not be set");
      assertEquals(Rcode.NOERROR, response.getRcode());
      assertEquals("failed.nsec3_ignored", getReason(response));
    } finally {
      Type.register(Type.DNSKEY, Type.string(Type.DNSKEY), () -> spy(DNSKEYRecord.class));
    }
  }

  void prepareTestPublicKeyLoadingException() {
    Name fakeName = Name.fromConstantString("nsec3.ingotronic.ch.");
    Type.register(
        Type.DNSKEY,
        Type.string(Type.DNSKEY),
        () -> {
          DNSKEYRecord throwingDnskey = spy(DNSKEYRecord.class);
          AtomicInteger invocationCount = new AtomicInteger(0);
          try {
            doAnswer(
                    (Answer<PublicKey>)
                        a -> {
                          if (((DNSKEYRecord) a.getMock()).getName().equals(fakeName)) {
                            if (invocationCount.getAndIncrement() == 3) {
                              throwDnssecException();
                            }
                            return (PublicKey) a.callRealMethod();
                          }
                          return (PublicKey) a.callRealMethod();
                        })
                .when(throwingDnskey)
                .getPublicKey();
          } catch (DNSSECException e) {
            throw new RuntimeException(e);
          }
          return throwingDnskey;
        });
  }

  private void throwDnssecException() throws DNSSECException {
    try {
      Constructor<DNSSECException> c = DNSSECException.class.getDeclaredConstructor(String.class);
      c.setAccessible(true);
      throw c.newInstance("mock-text");
    } catch (NoSuchMethodException
        | IllegalAccessException
        | InvocationTargetException
        | InstantiationException e) {
      throw new RuntimeException(e);
    }
  }
}

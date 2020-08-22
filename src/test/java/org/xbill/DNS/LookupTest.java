// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.xbill.DNS.ResolverConfig.CONFIGPROVIDER_SKIP_INIT;

import java.io.IOException;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

public class LookupTest {
  @Test
  void testNdots1() throws IOException {
    try {
      System.setProperty(CONFIGPROVIDER_SKIP_INIT, "true");
      Resolver mockResolver = Mockito.mock(Resolver.class);
      Name queryName = Name.fromConstantString("example.com");
      when(mockResolver.send(any(Message.class)))
          .thenAnswer(
              (Answer<Message>)
                  invocation -> {
                    Message query = invocation.getArgument(0);
                    Message answer = new Message(query.getHeader().getID());
                    answer.addRecord(query.getQuestion(), Section.QUESTION);
                    answer.addRecord(
                        new ARecord(
                            query.getQuestion().getName(),
                            DClass.IN,
                            60,
                            InetAddress.getByName("127.0.0.1")),
                        Section.ANSWER);
                    return answer;
                  });
      Lookup l = new Lookup(queryName, Type.A);
      l.setCache(null);
      l.setResolver(mockResolver);
      l.setSearchPath("namespace.svc.cluster.local", "svc.cluster.local", "cluster.local");
      Record[] results = l.run();
      verify(mockResolver, times(1)).send(any(Message.class));
      assertEquals(1, results.length);
    } finally {
      System.clearProperty(CONFIGPROVIDER_SKIP_INIT);
    }
  }

  @Test
  void testNdotsFallbackToAbsolute() throws IOException {
    try {
      System.setProperty(CONFIGPROVIDER_SKIP_INIT, "true");
      Resolver mockResolver = Mockito.mock(Resolver.class);
      Name queryName = Name.fromConstantString("example.com");
      when(mockResolver.send(any(Message.class)))
          .thenAnswer(
              (Answer<Message>)
                  invocation -> {
                    Message query = invocation.getArgument(0);
                    Message answer = new Message(query.getHeader().getID());
                    answer.addRecord(query.getQuestion(), Section.QUESTION);
                    if (query.getQuestion().getName().labels() == 3) {
                      answer.addRecord(
                          new ARecord(
                              query.getQuestion().getName(),
                              DClass.IN,
                              60,
                              InetAddress.getByName("127.0.0.1")),
                          Section.ANSWER);
                    } else {
                      answer.getHeader().setRcode(Rcode.NXDOMAIN);
                    }
                    return answer;
                  });
      Lookup l = new Lookup(queryName, Type.A);
      l.setCache(null);
      l.setResolver(mockResolver);
      l.setNdots(5);
      l.setSearchPath("namespace.svc.cluster.local", "svc.cluster.local", "cluster.local");
      Record[] results = l.run();
      verify(mockResolver, times(4)).send(any(Message.class));
      assertEquals(1, results.length);
    } finally {
      System.clearProperty(CONFIGPROVIDER_SKIP_INIT);
    }
  }
}

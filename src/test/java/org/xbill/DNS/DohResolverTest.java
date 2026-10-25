// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.spy;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpVersion;
import io.vertx.junit5.Checkpoint;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.stubbing.Answer;

@ExtendWith(VertxExtension.class)
@Slf4j
class DohResolverTest {
  private final Name queryName = Name.fromConstantString("example.com.");
  private final Record qr = Record.newRecord(queryName, Type.A, DClass.IN);
  private final Message qm = Message.newQuery(qr);
  private final Message a = new Message();
  private boolean allRequestsUseTimeout = true;

  @BeforeEach
  void beforeEach() throws UnknownHostException {
    Record ar =
        new ARecord(
            Name.fromConstantString("example.com."),
            DClass.IN,
            3600,
            InetAddress.getByName("127.0.0.1"));
    a.addRecord(qr, Section.QUESTION);
    a.addRecord(ar, Section.ANSWER);
  }

  private DohResolver getResolver() {
    return new DohResolver("http://localhost");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void simpleResolve(boolean usePost, Vertx vertx, VertxTestContext context) {
    DohResolver resolver = getResolver();
    resolver.setUsePost(usePost);
    setupResolverWithServer(resolver, Duration.ZERO, 200, 1, vertx, context)
        .onSuccess(
            server ->
                Future.fromCompletionStage(resolver.sendAsync(qm))
                    .onComplete(assertOnValidReply(context)));
  }

  @ParameterizedTest
  @CsvSource({
    "false,,,,true",
    "true,,,,true",
    "false,a.,,,false",
    "true,a.,,,false",
    "false,,3,,false",
    "true,,3,,false",
    "false,a.,3,,false",
    "true,a.,3,,false",
    "false,,,28,false",
    "true,,,28,false",
    "false,a.,,28,false",
    "true,a.,,28,false",
    "false,a.,3,28,false",
    "true,a.,3,28,false",
    "false,,3,28,false",
    "true,,3,28,false",
  })
  void simpleResolveInvalidReply(
      boolean usePost,
      String name,
      Integer dclass,
      Integer type,
      boolean isValid,
      Vertx vertx,
      VertxTestContext context) {
    DohResolver resolver = getResolver();
    resolver.setUsePost(usePost);
    setupServer(
            qm,
            a,
            Duration.ZERO,
            200,
            1,
            context,
            vertx,
            m -> {
              Record question = m.getQuestion();
              m.removeAllRecords(Section.QUESTION);
              m.addRecord(
                  Record.newRecord(
                      name == null ? question.getName() : Name.fromConstantString(name),
                      type == null ? question.getType() : type,
                      dclass == null ? question.getDClass() : dclass),
                  Section.QUESTION);
            })
        .onSuccess(
            server -> {
              resolver.setUriTemplate("http://localhost:" + server.actualPort());
              Future.fromCompletionStage(resolver.sendAsync(qm))
                  .onComplete(
                      isValid ? assertOnValidReply(context) : assertOnInvalidReply(context));
            });
  }

  private Handler<AsyncResult<Message>> assertOnInvalidReply(VertxTestContext context) {
    return context.failing(
        result ->
            context.verify(
                () -> {
                  assertThat(result).hasRootCauseInstanceOf(WireParseException.class);
                  context.completeNow();
                }));
  }

  private Handler<AsyncResult<Message>> assertOnValidReply(VertxTestContext context) {
    return context.succeeding(
        result ->
            context.verify(
                () -> {
                  assertThat(result.getRcode()).isEqualTo(Rcode.NOERROR);
                  assertThat(result.getHeader().getID()).isZero();
                  assertThat(result.getQuestion().getName()).isEqualTo(queryName);
                  context.completeNow();
                }));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void timeoutResolve(boolean usePost, Vertx vertx, VertxTestContext context) {
    DohResolver resolver = getResolver();
    resolver.setTimeout(Duration.ofSeconds(1));
    resolver.setUsePost(usePost);
    setupResolverWithServer(resolver, Duration.ofSeconds(5), 200, 1, vertx, context)
        .onSuccess(
            server ->
                Future.fromCompletionStage(resolver.sendAsync(qm))
                    .onComplete(
                        context.failing(
                            ex ->
                                context.verify(
                                    () -> {
                                      assertThat(
                                              ex.getCause() instanceof TimeoutException
                                                  || ex.getMessage().contains("timed out"))
                                          .isTrue();
                                      context.completeNow();
                                    }))));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void servfailResolve(boolean usePost, Vertx vertx, VertxTestContext context) {
    DohResolver resolver = getResolver();
    resolver.setUsePost(usePost);
    setupResolverWithServer(resolver, Duration.ZERO, 301, 1, vertx, context)
        .onSuccess(
            server ->
                Future.fromCompletionStage(resolver.sendAsync(qm))
                    .onComplete(
                        context.succeeding(
                            result ->
                                context.verify(
                                    () -> {
                                      assertThat(result.getRcode()).isEqualTo(Rcode.SERVFAIL);
                                      context.completeNow();
                                    }))));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void limitRequestsResolve(boolean usePost, Vertx vertx, VertxTestContext context) {
    DohResolver resolver = new DohResolver("http://localhost", 5, Duration.ofMinutes(2));
    resolver.setUsePost(usePost);
    int requests = 100;
    Checkpoint cpPass = context.checkpoint(requests);
    setupResolverWithServer(resolver, Duration.ofMillis(100), 200, 5, vertx, context)
        .onSuccess(
            server -> {
              for (int i = 0; i < requests; i++) {
                resolver
                    .sendAsync(qm)
                    .whenComplete(
                        (result, ex) -> {
                          if (ex == null) {
                            cpPass.flag();
                          } else {
                            context.failNow(ex);
                          }
                        });
              }
            });
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void initialRequestSlowResolve(boolean usePost, Vertx vertx, VertxTestContext context) {
    DohResolver resolver = new DohResolver("http://localhost", 2, Duration.ofMinutes(2));
    resolver.setUsePost(usePost);
    int requests = 20;
    allRequestsUseTimeout = false;
    Checkpoint cpPass = context.checkpoint(requests);
    setupResolverWithServer(resolver, Duration.ofSeconds(1), 200, 2, vertx, context)
        .onSuccess(
            server -> {
              for (int i = 0; i < requests; i++) {
                resolver
                    .sendAsync(qm)
                    .whenComplete(
                        (result, ex) -> {
                          if (ex == null) {
                            cpPass.flag();
                          } else {
                            context.failNow(ex);
                          }
                        });
              }
            });
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void initialRequestTimeoutResolve(boolean usePost, Vertx vertx, VertxTestContext context) {
    DohResolver resolver = new DohResolver("http://localhost", 2, Duration.ofMinutes(2));
    resolver.setUsePost(usePost);
    resolver.setTimeout(Duration.ofSeconds(1));
    int requests = 20;
    allRequestsUseTimeout = false;
    Checkpoint cpPass = context.checkpoint(requests - 1);
    Checkpoint cpFail = context.checkpoint();
    setupResolverWithServer(resolver, Duration.ofSeconds(2), 200, 2, vertx, context)
        .onSuccess(
            server -> {
              Message q = qm.clone();
              q.getHeader().setID(0);
              resolver
                  .sendAsync(q)
                  .whenComplete(
                      (result, ex) -> {
                        if (ex == null) {
                          context.failNow("First request succeeded");
                        } else {
                          cpFail.flag();
                        }
                      });
              vertx.setTimer(
                  1000,
                  timer -> {
                    for (int i = 1; i < requests; i++) {
                      Message qq = qm.clone();
                      qq.getHeader().setID(i);
                      resolver
                          .sendAsync(qq)
                          .whenComplete(
                              (result, ex) -> {
                                if (ex == null) {
                                  cpPass.flag();
                                } else {
                                  context.failNow("Request failed");
                                }
                              });
                    }
                  });
            });
  }

  private Future<HttpServer> setupResolverWithServer(
      DohResolver resolver,
      Duration responseDelay,
      int statusCode,
      int maxConcurrentRequests,
      Vertx vertx,
      VertxTestContext context) {
    return setupServer(
            qm, a, responseDelay, statusCode, maxConcurrentRequests, context, vertx, null)
        .onSuccess(server -> resolver.setUriTemplate("http://localhost:" + server.actualPort()));
  }

  @EnabledForJreRange(
      min = JRE.JAVA_9,
      disabledReason = "Java 8 implementation doesn't have the initial request guard")
  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void initialRequestGuardIfIdleConnectionTimeIsLargerThanSystemNanoTime(
      boolean usePost, Vertx vertx, VertxTestContext context) {
    AtomicLong startNanos = new AtomicLong(System.nanoTime());
    DohResolver resolver = spy(new DohResolver("http://localhost", 2, Duration.ofMinutes(2)));
    resolver.setTimeout(Duration.ofSeconds(1));
    resolver.setUsePost(usePost);
    // Simulate a nanoTime value that is lower than the idle timeout
    doAnswer((Answer<Long>) invocationOnMock -> System.nanoTime() - startNanos.get())
        .when(resolver)
        .getNanoTime();

    // Just add a 100ms delay before responding to the 1st call
    // to simulate a 'concurrent doh request' for the 2nd call,
    // then let the fake dns server respond to the 2nd call ASAP.
    allRequestsUseTimeout = false;

    // idleConnectionTimeout = 2s, lastRequest = 0L
    // Ensure idleConnectionTimeout < System.nanoTime() - lastRequest (3s)

    // Timeline:
    //         |<-------- 100ms -------->|
    //         ↑                         ↑
    //  1st call sent              response of 1st call
    //         |20ms|<------ 80ms ------>|<------ few millis ------->|
    //              ↑ wait until 1st call ↑                           ↑
    //       2nd call begin         2nd call sent            response of 2nd call

    AtomicBoolean firstCallCompleted = new AtomicBoolean(false);

    setupResolverWithServer(resolver, Duration.ofMillis(100L), 200, 2, vertx, context)
        .onSuccess(
            server -> {
              // First call
              CompletionStage<Message> firstCall =
                  resolver.sendAsync(qm).whenComplete((msg, ex) -> firstCallCompleted.set(true));

              // Ensure second call was made after first call and uses a different query
              startNanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(20));
              CompletionStage<Message> secondCall = resolver.sendAsync(Message.newQuery(qr));

              Future.fromCompletionStage(firstCall)
                  .onComplete(
                      context.succeeding(
                          result ->
                              context.verify(
                                  () -> {
                                    assertThat(result.getRcode()).isEqualTo(Rcode.NOERROR);
                                    assertThat(result.getHeader().getID()).isZero();
                                    assertThat(result.getQuestion().getName()).isEqualTo(queryName);
                                  })));

              Future.fromCompletionStage(secondCall)
                  .onComplete(
                      context.succeeding(
                          result ->
                              context.verify(
                                  () -> {
                                    assertThat(firstCallCompleted.get()).isTrue();
                                    assertThat(result.getRcode()).isEqualTo(Rcode.NOERROR);
                                    assertThat(result.getHeader().getID()).isZero();
                                    assertThat(result.getQuestion().getName()).isEqualTo(queryName);
                                    // Complete context after the 2nd call was completed.
                                    context.completeNow();
                                  })));
            });
  }

  private Future<HttpServer> setupServer(
      Message expectedDnsRequest,
      Message dnsResponse,
      Duration serverProcessingTime,
      int statusCode,
      int maxConcurrentRequests,
      VertxTestContext context,
      Vertx vertx,
      Consumer<Message> responseInterceptor) {
    HttpVersion version =
        System.getProperty("java.version").startsWith("1.")
            ? HttpVersion.HTTP_1_1
            : HttpVersion.HTTP_2;
    AtomicInteger requestCount = new AtomicInteger(0);
    AtomicInteger concurrentRequests = new AtomicInteger(0);
    return vertx
        .createHttpServer(
            new HttpServerOptions().setAlpnVersions(Collections.singletonList(version)))
        .requestHandler(
            httpRequest -> {
              int thisRequestNum = requestCount.incrementAndGet();
              int count = concurrentRequests.incrementAndGet();
              if (count > maxConcurrentRequests) {
                context.failNow(
                    "Concurrent requests exceeded: " + count + " > " + maxConcurrentRequests);
                return;
              }

              httpRequest.endHandler(v -> concurrentRequests.decrementAndGet());
              httpRequest.bodyHandler(
                  body -> {
                    context.verify(
                        () -> {
                          assertThat(httpRequest.getHeader(HttpHeaderNames.CONTENT_TYPE))
                              .isEqualTo("application/dns-message");
                          byte[] actualDnsRequestBytes;
                          if (httpRequest.method() == HttpMethod.POST) {
                            actualDnsRequestBytes = body.getBytes();
                          } else {
                            actualDnsRequestBytes =
                                Base64.getDecoder().decode(httpRequest.getParam("dns"));
                          }

                          Message actualDnsRequest = new Message(actualDnsRequestBytes);
                          assertThat(actualDnsRequest.getHeader().getID()).isZero();
                          assertThat(actualDnsRequest.getQuestion())
                              .isEqualTo(expectedDnsRequest.getQuestion());
                        });
                    Message dnsResponseCopy = dnsResponse.clone();
                    dnsResponseCopy.getHeader().setID(0);
                    if (responseInterceptor != null) {
                      responseInterceptor.accept(dnsResponseCopy);
                    }
                    if (!serverProcessingTime.isZero()
                        && (thisRequestNum == 1 || allRequestsUseTimeout)) {
                      vertx.setTimer(
                          serverProcessingTime.toMillis(),
                          timer ->
                              httpRequest
                                  .response()
                                  .setStatusCode(statusCode)
                                  .end(Buffer.buffer(dnsResponseCopy.toWire())));
                    } else {
                      httpRequest
                          .response()
                          .setStatusCode(statusCode)
                          .end(Buffer.buffer(dnsResponseCopy.toWire()));
                    }
                  });
            })
        .listen(0);
  }
}

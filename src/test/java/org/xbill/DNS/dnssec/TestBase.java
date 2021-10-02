// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.EDNSOption.Code;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

public abstract class TestBase {
  private static final Logger logger = LoggerFactory.getLogger(TestBase.class);

  private static final boolean offline = !Boolean.getBoolean("dnsjava.dnssec.online");
  private static final boolean partialOffline =
      "partial".equals(System.getProperty("dnsjava.dnssec.offline"));
  private static final boolean record = Boolean.getBoolean("dnsjava.dnssec.record");
  private boolean unboundTest = false;
  private boolean alwaysOffline = false;

  private final Map<String, Message> queryResponsePairs = new HashMap<>();
  private final MessageReader messageReader = new MessageReader();
  private FileWriter w;

  protected static final String localhost = "127.0.0.1";
  protected ValidatingResolver resolver;
  protected Clock resolverClock;
  protected String testName;

  @BeforeEach
  void beforeEach(TestInfo description) throws IOException, DNSSECException {
    starting(description);
    setup();
  }

  private void starting(TestInfo description) {
    unboundTest = false;
    testName = description.getTestMethod().orElseThrow(RuntimeException::new).getName();
    if (description.getDisplayName().startsWith(testName + "_")) {
      testName = description.getDisplayName();
    }
    resolverClock = mock(Clock.class);

    try {
      // do not record or process unbound unit tests offline
      alwaysOffline = description.getTestMethod().get().getAnnotation(AlwaysOffline.class) != null;
      if (description
          .getTestClass()
          .orElseThrow(RuntimeException::new)
          .getName()
          .toLowerCase(Locale.ROOT)
          .contains("unbound")) {
        unboundTest = true;
        return;
      }

      DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
      String filename =
          "/recordings/"
              + description.getTestClass().get().getName().replace(".", "_")
              + "/"
              + testName;
      File f = new File("./src/test/resources" + filename);
      if ((record || !f.exists()) && !alwaysOffline) {
        resolverClock = Clock.systemUTC();
        f.getParentFile().getParentFile().mkdir();
        f.getParentFile().mkdir();
        w = new FileWriter(f.getAbsoluteFile());
        w.write("#Date: " + ZonedDateTime.now().format(formatter));
        w.write("\n");
      } else if (offline || partialOffline || alwaysOffline) {
        PrepareMocks pm = description.getTestMethod().get().getAnnotation(PrepareMocks.class);
        if (pm != null) {
          Method m = TestBase.this.getClass().getDeclaredMethod(pm.value());
          m.setAccessible(true);
          m.invoke(TestBase.this);
        }

        InputStream stream = getClass().getResourceAsStream(filename);
        if (stream != null) {
          BufferedReader r = new BufferedReader(new InputStreamReader(stream));
          String date = r.readLine().substring("#Date: ".length());
          when(resolverClock.instant())
              .thenReturn(ZonedDateTime.parse(date, formatter).toInstant());

          Message m;
          while ((m = messageReader.readMessage(r)) != null) {
            queryResponsePairs.put(key(m), m);
          }

          r.close();
        }
      }
    } catch (Exception e) {
      System.err.println(e);
      throw new RuntimeException(e);
    }
  }

  @AfterEach
  void finished() {
    try {
      if (w != null) {
        w.flush();
        w.close();
        w = null;
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @BeforeAll
  static void setupClass() {
    R.setBundle(null);
    R.setUseNeutralMessages(true);
  }

  private void setup() throws NumberFormatException, IOException, DNSSECException {
    resolver =
        new ValidatingResolver(
            new SimpleResolver("8.8.4.4") {
              @Override
              public CompletionStage<Message> sendAsync(Message query) {
                logger.info("---{}", key(query));
                Message response = queryResponsePairs.get(key(query));
                if (response != null) {
                  return CompletableFuture.completedFuture(response);
                } else if ((offline && !partialOffline) || unboundTest || alwaysOffline) {
                  fail("Response for " + key(query) + " not found.");
                }

                Message networkResult;
                try {
                  networkResult = super.sendAsync(query).toCompletableFuture().get();
                  if (w != null) {
                    w.write(networkResult.toString());
                    w.write("\n\n###############################################\n\n");
                  }
                } catch (IOException | InterruptedException | ExecutionException e) {
                  CompletableFuture<Message> f = new CompletableFuture<>();
                  f.completeExceptionally(e);
                  return f;
                }

                return CompletableFuture.completedFuture(networkResult);
              }
            },
            resolverClock);

    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors"));
  }

  protected void add(Message m) throws IOException {
    this.add(key(m), m, true);
  }

  protected void add(String query, Message response) throws IOException {
    this.add(query, response, true);
  }

  protected void add(String query, Message response, boolean clear) throws IOException {
    queryResponsePairs.put(query, messageFromString(response.toString()));

    // reset the resolver so any cached stuff is cleared
    if (!clear) {
      return;
    }

    try {
      setup();
    } catch (NumberFormatException | DNSSECException e) {
      throw new IOException(e);
    }
  }

  protected Message get(Name target, int type) {
    return queryResponsePairs.get(key(target, type));
  }

  protected void clear() {
    queryResponsePairs.clear();
  }

  protected Message createMessage(String query) throws IOException {
    return Message.newQuery(
        Record.newRecord(
            Name.fromString(query.split("/")[0]), Type.value(query.split("/")[1]), DClass.IN));
  }

  protected Message messageFromString(String message) throws IOException {
    return messageReader.readMessage(new StringReader(message));
  }

  protected String firstA(Message response) {
    List<RRset> sectionRRsets = response.getSectionRRsets(Section.ANSWER);
    if (!sectionRRsets.isEmpty()) {
      for (Record r : sectionRRsets.get(0).rrs()) {
        if (r.getType() == Type.A) {
          return ((ARecord) r).getAddress().getHostAddress();
        }
      }
    }

    return null;
  }

  protected int getEdeReason(Message m) {
    return Optional.ofNullable(m.getOPT())
        .flatMap(
            opt ->
                opt.getOptions(Code.EDNS_EXTENDED_ERROR).stream()
                    .filter(o -> o instanceof ExtendedErrorCodeOption)
                    .findFirst()
                    .map(o -> ((ExtendedErrorCodeOption) o).getErrorCode()))
        .orElse(-1);
  }

  protected String getReason(Message m) {
    for (RRset set : m.getSectionRRsets(Section.ADDITIONAL)) {
      if (set.getName().equals(Name.root)
          && set.getType() == Type.TXT
          && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
        StringBuilder sb = new StringBuilder();
        List<String> strings = ((TXTRecord) set.first()).getStrings();
        for (String part : strings) {
          sb.append(part);
        }

        return sb.toString();
      }
    }

    return null;
  }

  protected boolean isEmptyAnswer(Message response) {
    return response.getSectionRRsets(Section.ANSWER).isEmpty();
  }

  private String key(Name n, int t) {
    return n + "/" + Type.string(t);
  }

  private String key(Record r) {
    return key(r.getName(), r.getType());
  }

  private String key(Message m) {
    return key(m.getQuestion());
  }

  protected Record toRecord(String data) {
    try {
      InputStream in = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
      Master m = new Master(in, Name.root);
      return m.nextRecord();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}

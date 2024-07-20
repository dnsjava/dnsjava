// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.openjdk.jcstress.annotations.Expect.ACCEPTABLE;
import static org.openjdk.jcstress.annotations.Expect.ACCEPTABLE_INTERESTING;
import static org.openjdk.jcstress.annotations.Expect.FORBIDDEN;

import java.net.InetAddress;
import java.util.List;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.openjdk.jcstress.Main;
import org.openjdk.jcstress.annotations.Actor;
import org.openjdk.jcstress.annotations.Arbiter;
import org.openjdk.jcstress.annotations.Description;
import org.openjdk.jcstress.annotations.JCStressTest;
import org.openjdk.jcstress.annotations.Outcome;
import org.openjdk.jcstress.annotations.State;
import org.openjdk.jcstress.infra.results.II_Result;
import org.openjdk.jcstress.infra.results.L_Result;

class ZoneStressTest {
  @Test
  @Tag("concurrency")
  void runZoneConcurrentReadStressTest() throws Exception {
    // IntelliJ doesn't properly run the JCStress' annotation processor,
    // use Maven to compile (and disable build-before-run)
    Main.main(
        new String[] {"-r", "target/jcstress", "-t", ZoneStressTest.class.getSimpleName(), "-v"});
  }

  public static class ZoneStressTestBase {
    protected final Name zoneName;
    protected final Zone zone;
    protected final ARecord A1;
    protected final ARecord A2_1;
    protected final ARecord A2_2;
    protected final Name mxName;
    protected final InetAddress localhost4_1;
    protected final InetAddress localhost4_2;
    protected final InetAddress localhost4_3;

    @SneakyThrows
    public ZoneStressTestBase() {
      zoneName = Name.fromConstantString("example.");
      mxName = new Name("mx", zoneName);
      SOARecord SOA1 =
          new SOARecord(
              zoneName,
              DClass.IN,
              3600L,
              Name.fromConstantString("nameserver."),
              new Name("hostadmin", zoneName),
              1,
              21600L,
              7200L,
              2160000L,
              3600L);
      NSRecord NS1 =
          new NSRecord(zoneName, DClass.IN, 300L, Name.fromConstantString("nameserver1."));

      localhost4_1 = InetAddress.getByName("127.0.0.1");
      localhost4_2 = InetAddress.getByName("127.0.0.2");
      localhost4_3 = InetAddress.getByName("127.0.0.3");
      A1 = new ARecord(new Name("test1", zoneName), DClass.IN, 3600, localhost4_1);
      A2_1 = new ARecord(new Name("test2", zoneName), DClass.IN, 3600, localhost4_2);
      A2_2 = new ARecord(new Name("test2", zoneName), DClass.IN, 3600, localhost4_3);

      Record[] zoneRecords =
          new Record[] {
            SOA1, NS1, A1, A2_1, A2_2,
          };
      zone = new Zone(zoneName, zoneRecords);
    }
  }

  @JCStressTest
  @Description("Test concurrent writes to the same RRset")
  @Outcome(
      id = {"10, 20", "20, 10"},
      expect = ACCEPTABLE)
  @Outcome(expect = FORBIDDEN, desc = "Other cases are forbidden.")
  @State
  public static class Write extends ZoneStressTestBase {
    @Actor
    public void writer1() {
      zone.addRecord(new MXRecord(mxName, DClass.IN, 3600, 10, A1.getName()));
    }

    @Actor
    public void writer2() {
      zone.addRecord(new MXRecord(mxName, DClass.IN, 3600, 20, A2_1.getName()));
    }

    @Arbiter
    public void reader(II_Result r) {
      r.r1 = poll(0);
      r.r2 = poll(1);
    }

    private int poll(int index) {
      List<Record> rrs = zone.findExactMatch(mxName, Type.MX).rrs(false);
      return rrs.size() > index ? ((MXRecord) rrs.get(index)).getPriority() : -1;
    }
  }

  @JCStressTest
  @Description("Test concurrent add/read to the same RRset")
  @Outcome(
      id = {"[127.0.0.1]", "[127.0.0.1, 127.0.0.2]"},
      expect = ACCEPTABLE)
  @Outcome(
      id = {"[127.0.0.2, 127.0.0.1]"},
      expect = ACCEPTABLE_INTERESTING)
  @Outcome(expect = FORBIDDEN, desc = "Other cases are forbidden.")
  @State
  public static class AddRead extends ZoneStressTestBase {
    @Actor
    public void writer() {
      zone.addRecord(new ARecord(A1.getName(), DClass.IN, 3600, localhost4_2));
    }

    @Actor
    public void reader(L_Result r) {
      r.r1 =
          zone.findExactMatch(A1.getName(), Type.A).rrs(false).stream()
              .map(record -> ((ARecord) record).getAddress().getHostAddress())
              .collect(Collectors.toList());
    }
  }

  @JCStressTest
  @Description("Test concurrent remove/read to the same RRset")
  @Outcome(
      id = {"[127.0.0.3]", "[127.0.0.2, 127.0.0.3]"},
      expect = ACCEPTABLE)
  @Outcome(expect = FORBIDDEN, desc = "Other cases are forbidden.")
  @State
  public static class RemoveRead extends ZoneStressTestBase {
    @Actor
    public void writer() {
      zone.removeRecord(A2_1);
    }

    @Actor
    public void reader(L_Result r) {
      r.r1 =
          zone.findExactMatch(A2_1.getName(), Type.A).rrs(false).stream()
              .map(record -> ((ARecord) record).getAddress().getHostAddress())
              .collect(Collectors.toList());
    }
  }

  @JCStressTest
  @Description("Test concurrent add/read to a new RRset")
  @Outcome(
      id = {"1, -1", "1, 1"},
      expect = ACCEPTABLE)
  @Outcome(expect = FORBIDDEN, desc = "Other cases are forbidden.")
  @State
  public static class AddReadDifferentRRset extends ZoneStressTestBase {
    private final Name testName;

    @SneakyThrows
    public AddReadDifferentRRset() {
      testName = new Name("test", zoneName);
    }

    @Actor
    public void writer() {
      zone.addRecord(new ARecord(testName, DClass.IN, 3600, localhost4_1));
    }

    @Actor
    public void reader(II_Result r) {
      r.r1 = poll(A1.getName());
      r.r2 = poll(testName);
    }

    private int poll(Name name) {
      RRset rrs = zone.findExactMatch(name, Type.A);
      return rrs != null ? rrs.size() : -1;
    }
  }

  @JCStressTest
  @Description("Test concurrent add and iteration")
  @Outcome(
      id = {"4, -1", "5, 1"},
      expect = ACCEPTABLE)
  @Outcome(expect = FORBIDDEN, desc = "Other cases are forbidden.")
  @State
  public static class AddNewRRsetAndIterate extends ZoneStressTestBase {
    private final Name testName;

    @SneakyThrows
    public AddNewRRsetAndIterate() {
      testName = new Name("test", zoneName);
    }

    @Actor
    public void writer() {
      zone.addRecord(new ARecord(testName, DClass.IN, 3600, localhost4_1));
    }

    @Actor
    public void reader(II_Result r) {
      r.r2 = -1;
      for (RRset rr : zone) {
        r.r1++;
        if (rr.getName().equals(testName)) {
          r.r2 = rr.size();
        }
      }
    }
  }

  @JCStressTest
  @Description("Test concurrent add and iteration")
  @Outcome(
      id = {"4, 1", "4, 2"},
      expect = ACCEPTABLE)
  @Outcome(expect = FORBIDDEN, desc = "Other cases are forbidden.")
  @State
  public static class AddToRRsetAndIterate extends ZoneStressTestBase {
    @Actor
    public void writer() {
      zone.addRecord(new ARecord(A1.getName(), DClass.IN, 3600, localhost4_2));
    }

    @Actor
    public void reader(II_Result r) {
      r.r2 = -1;
      for (RRset rr : zone) {
        r.r1++;
        if (rr.getName().equals(A1.getName())) {
          r.r2 = rr.size();
        }
      }
    }
  }
}

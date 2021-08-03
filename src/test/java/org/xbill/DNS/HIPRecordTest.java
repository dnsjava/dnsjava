// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.IPSECKEYRecord.Algorithm;

public class HIPRecordTest {
  private Name exampleCom = Name.fromConstantString("www.example.com.");
  private Name rvs = Name.fromConstantString("rvs.example.com.");
  private Name rvs1 = Name.fromConstantString("rvs1.example.com.");
  private Name rvs2 = Name.fromConstantString("rvs2.example.com.");
  private List<Name> servers = new ArrayList<>();

  @BeforeEach
  void beforeEach() {
    servers.add(rvs1);
    servers.add(rvs2);
  }

  @Test
  void testRfcExample1() throws IOException, DNSSECException {
    String example =
        "www.example.com.      IN  HIP ( 2 200100107B1A74DF365639CC39F1D578\n"
            + "                          AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D )";
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), Name.root, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(exampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertTrue(pk instanceof RSAPublicKey);
      assertEquals(0, hip.getRvServers().size());

      DNSOutput out = new DNSOutput();
      hip.toWire(out, Section.ANSWER, null);
      HIPRecord hip2 = (HIPRecord) Record.fromWire(out.toByteArray(), Section.ANSWER);
      assertEquals(hip, hip2);
    }
  }

  @Test
  void testRfcExample2() throws IOException, DNSSECException {
    String example =
        "www.example.com.      IN  HIP ( 2 200100107B1A74DF365639CC39F1D578\n"
            + "                          AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D\n"
            + "                          rvs.example.com. )";
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), Name.root, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(exampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertTrue(pk instanceof RSAPublicKey);
      assertEquals(1, hip.getRvServers().size());
      assertEquals(rvs, hip.getRvServers().get(0));

      DNSOutput out = new DNSOutput();
      hip.toWire(out, Section.ANSWER, null);
      HIPRecord hip2 = (HIPRecord) Record.fromWire(out.toByteArray(), Section.ANSWER);
      assertEquals(hip, hip2);
    }
  }

  @Test
  void testRfcExample3() throws IOException, DNSSECException {
    String example =
        "www.example.com.      IN  HIP ( 2 200100107B1A74DF365639CC39F1D578\n"
            + "                          AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D\n"
            + "                          rvs1.example.com.\n"
            + "                          rvs2.example.com. )";
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), Name.root, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(exampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertTrue(pk instanceof RSAPublicKey);
      assertEquals(2, hip.getRvServers().size());
      assertEquals(rvs1, hip.getRvServers().get(0));
      assertEquals(rvs2, hip.getRvServers().get(1));

      DNSOutput out = new DNSOutput();
      hip.toWire(out, Section.ANSWER, null);
      HIPRecord hip2 = (HIPRecord) Record.fromWire(out.toByteArray(), Section.ANSWER);
      assertEquals(hip, hip2);
    }
  }

  @Test
  void testHipToString() {
    Options.unset("multiline");
    HIPRecord hip =
        new HIPRecord(
            exampleCom, DClass.IN, 900, new byte[] {1, 2, 3}, Algorithm.RSA, new byte[] {1, 2, 3});
    assertEquals("2 010203 AQID", hip.rrToString());
  }

  @Test
  void testHipToStringServers() {
    Options.unset("multiline");
    HIPRecord hip =
        new HIPRecord(
            exampleCom,
            DClass.IN,
            900,
            new byte[] {1, 2, 3},
            Algorithm.RSA,
            new byte[] {1, 2, 3},
            servers);
    assertEquals("2 010203 AQID " + rvs1.toString() + " " + rvs2.toString(), hip.rrToString());
  }

  @Test
  void testHipToStringMultiline() {
    Options.set("multiline");
    HIPRecord hip =
        new HIPRecord(
            exampleCom, DClass.IN, 900, new byte[] {1, 2, 3}, Algorithm.RSA, new byte[] {1, 2, 3});
    assertEquals("( 2 010203\n\tAQID )", hip.rrToString());
  }

  @Test
  void testHipToStringServersMultiline() {
    Options.set("multiline");
    HIPRecord hip =
        new HIPRecord(
            exampleCom,
            DClass.IN,
            900,
            new byte[] {1, 2, 3},
            Algorithm.RSA,
            new byte[] {1, 2, 3},
            servers);
    assertEquals(
        "( 2 010203\n\t" + "AQID\n\t" + rvs1.toString() + "\n\t" + rvs2.toString() + " )",
        hip.rrToString());
  }
}

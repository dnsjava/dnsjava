// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.IPSECKEYRecord.Algorithm;

class HIPRecordTest {
  private final Name exampleCom = Name.fromConstantString("example.com.");
  private final Name wwwExampleCom = Name.fromConstantString("www.example.com.");
  private final Name rvs = Name.fromConstantString("rvs.example.com.");
  private final Name rvs1 = Name.fromConstantString("rvs1.example.com.");
  private final Name rvs2 = Name.fromConstantString("rvs2.example.com.");
  private final List<Name> servers = new ArrayList<>();

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
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), exampleCom, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(wwwExampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertInstanceOf(RSAPublicKey.class, pk);
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
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), exampleCom, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(wwwExampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertInstanceOf(RSAPublicKey.class, pk);
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
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), exampleCom, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(wwwExampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertInstanceOf(RSAPublicKey.class, pk);
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
  void testRelativeRv() throws IOException, DNSSECException {
    String example =
        "www.example.com.      IN  HIP ( 2 200100107B1A74DF365639CC39F1D578\n"
            + "                          AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D\n"
            + "                          rvs1\n"
            + "                          rvs2 )";
    try (Master m = new Master(new ByteArrayInputStream(example.getBytes()), exampleCom, 900)) {
      HIPRecord hip = (HIPRecord) m.nextRecord();
      assertEquals(wwwExampleCom, hip.getName());
      assertEquals(2, hip.getAlgorithm());
      PublicKey pk = hip.getPublicKey();
      assertInstanceOf(RSAPublicKey.class, pk);
      assertEquals(2, hip.getRvServers().size());
      assertThat(hip.getRvServers().get(0)).isEqualTo(rvs1);
      assertThat(hip.getRvServers().get(1)).isEqualTo(rvs2);
      assertThat(hip.getRvServers().get(0).isAbsolute()).isTrue();
      assertThat(hip.getRvServers().get(1).isAbsolute()).isTrue();

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
            wwwExampleCom,
            DClass.IN,
            900,
            new byte[] {1, 2, 3},
            Algorithm.RSA,
            new byte[] {1, 2, 3});
    assertEquals("2 010203 AQID", hip.rrToString());
  }

  @Test
  void testHipToStringServers() {
    Options.unset("multiline");
    HIPRecord hip =
        new HIPRecord(
            wwwExampleCom,
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
            wwwExampleCom,
            DClass.IN,
            900,
            new byte[] {1, 2, 3},
            Algorithm.RSA,
            new byte[] {1, 2, 3});
    assertEquals("( 2 010203\n\tAQID )", hip.rrToString());
  }

  @Test
  void testHipToStringServersMultiline() {
    Options.set("multiline");
    HIPRecord hip =
        new HIPRecord(
            wwwExampleCom,
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

  @Test
  void emptyHitInCtorThrows() {
    assertThatThrownBy(() -> new HIPRecord(Name.root, DClass.IN, 0, new byte[0], 0, new byte[1]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("hit is required and must be non-empty");
    assertThatThrownBy(() -> new HIPRecord(Name.root, DClass.IN, 0, null, 0, new byte[1]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("hit is required and must be non-empty");
  }

  @Test
  void emptyCertInCtorThrows() {
    assertThatThrownBy(() -> new HIPRecord(Name.root, DClass.IN, 0, new byte[1], 0, new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("key is required and must be non-empty");
    assertThatThrownBy(() -> new HIPRecord(Name.root, DClass.IN, 0, new byte[1], 0, (byte[]) null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("key is required and must be non-empty");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "", " ", " \"\"",
      })
  void emptyHitInPresentationThrows(String suffix) {
    try (Tokenizer t = new Tokenizer("2" + suffix)) {
      HIPRecord r = new HIPRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessageEndingWith("expected a hex string");
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "", " ", " \"\"",
      })
  void emptyCertInPresentationThrows(String suffix) {
    try (Tokenizer t = new Tokenizer("2 AB" + suffix)) {
      HIPRecord r = new HIPRecord();
      assertThatThrownBy(() -> r.rdataFromString(t, null))
          .isInstanceOf(TextParseException.class)
          .hasMessageMatching(
              "(public key is required and must be non-empty)|(.*expected a string)");
    }
  }

  @Test
  void tooShortInputFromWireThrows() {
    HIPRecord r = new HIPRecord();
    assertThatThrownBy(
            () ->
                r.rrFromWire(
                    new DNSInput(
                        new byte[] {
                          0, // hit length
                          0, // alg
                          // missing hit
                          // missing length
                          // missing cert
                        })))
        .isInstanceOf(WireParseException.class)
        .hasMessage("end of input");
  }

  @Test
  void emptyHitFromWireThrows() {
    HIPRecord r = new HIPRecord();
    assertThatThrownBy(
            () ->
                r.rrFromWire(
                    new DNSInput(
                        new byte[] {
                          0, // hit length
                          0, // alg
                          0, // cert length
                          1,
                          // missing hit
                          1, // cert
                        })))
        .isInstanceOf(WireParseException.class)
        .hasMessage("hit is required and must be non-empty");
  }

  @Test
  void emptyCertFromWireThrows() {
    HIPRecord r = new HIPRecord();
    assertThatThrownBy(
            () ->
                r.rrFromWire(
                    new DNSInput(
                        new byte[] {
                          1, // hit length
                          0, // alg
                          0, // cert length
                          0, 0xa, // hit
                          // missing cert
                        })))
        .isInstanceOf(WireParseException.class)
        .hasMessage("public key is required and must be non-empty");
  }
}

// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CAARecordTest {
  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_6arg() {
    CAARecord caa = new CAARecord(n, DClass.IN, 0, CAARecord.Flags.IssuerCritical, "1", "");
    assertEquals(CAARecord.Flags.IssuerCritical, caa.getFlags());
    assertEquals("1", caa.getTag());
    assertEquals("", caa.getValue());
    assertEquals(0, caa.getValueAsByteArray().length);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        0, 256,
      })
  void validateTagLengths(int tagLength) {
    String tag = new String(new char[tagLength]);
    assertThatThrownBy(
            () -> new CAARecord(n, DClass.IN, 3600, CAARecord.Flags.IssuerCritical, tag, ""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("invalid tag");
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 256, 300})
  void validateValueLengths(int valueLength) {
    String value = new String(new char[valueLength]);
    CAARecord caa = new CAARecord(n, DClass.IN, 3600, CAARecord.Flags.IssuerCritical, "1", value);
    assertThat(caa.getValueAsByteArray()).hasSize(valueLength);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer(CAARecord.Flags.IssuerCritical + " issue entrust.net");
    CAARecord caa = new CAARecord();
    caa.rdataFromString(t, null);
    assertEquals("issue", caa.getTag());
    assertEquals("entrust.net", caa.getValue());
    assertEquals("entrust.net", caa.getValue(false));
    assertArrayEquals("entrust.net".getBytes(StandardCharsets.UTF_8), caa.getValueAsByteArray());
  }

  @Test
  void validateLongValueCanRoundtrip() throws IOException {
    String value =
        IntStream.range(0, 360)
            .boxed()
            .map(
                i -> {
                  if (i < 120) {
                    return "a";
                  } else if (i == 120) {
                    return ".";
                  } else if (i < 240) {
                    return "b";
                  } else if (i == 240) {
                    return ".";
                  } else if (i < 360) {
                    return "c";
                  } else if (i == 360) {
                    return ".";
                  }
                  return "d";
                })
            .reduce("http://", (a, b) -> a + b);
    CAARecord caa = new CAARecord(n, DClass.IN, 3600, 1, "1", value);

    CAARecord caa2 = new CAARecord();
    DNSOutput out = new DNSOutput();
    caa.rrToWire(out, null, false);
    caa2.rrFromWire(new DNSInput(out.toByteArray()));
    assertThat(caa2.getValue()).hasToString(value);

    CAARecord caa3 = new CAARecord();
    caa3.rdataFromString(new Tokenizer(caa.rrToString()), Name.root);
    assertThat(caa3.getValue()).hasToString(value);
  }
}

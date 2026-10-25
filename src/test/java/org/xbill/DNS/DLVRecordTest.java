// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class DLVRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    DLVRecord dlv = new DLVRecord();
    assertThat(dlv.getFootprint()).isZero();
    assertThat(dlv.getAlgorithm()).isZero();
    assertThat(dlv.getDigestID()).isZero();
    assertThat(dlv.getDigest()).isNull();
  }

  @Test
  void ctor_7arg() {
    DLVRecord dlv = new DLVRecord(n, DClass.IN, 0, 1, 2, 3, "".getBytes());
    assertThat(dlv.getFootprint()).isOne();
    assertThat(dlv.getAlgorithm()).isEqualTo(2);
    assertThat(dlv.getDigestID()).isEqualTo(3);
    assertThat(dlv.getDigest()).isEmpty();
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("60485 5 1 CAFEBABE");
    DLVRecord dlv = new DLVRecord();
    dlv.rdataFromString(t, null);
    assertThat(dlv.getFootprint()).isEqualTo(60485);
    assertThat(dlv.getAlgorithm()).isEqualTo(5);
    assertThat(dlv.getDigestID()).isOne();
    assertThat(dlv.getDigest()).hasSize(4);
  }
}

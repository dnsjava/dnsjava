// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class MINFORecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_5arg() {
    Name respAddress = Name.fromConstantString("example.com.");
    Name errorAddress = Name.fromConstantString("error.com.");
    MINFORecord minfo = new MINFORecord(n, DClass.IN, 0, respAddress, errorAddress);
    assertThat(minfo.getResponsibleAddress()).isEqualTo(respAddress);
    assertThat(minfo.getErrorAddress()).isEqualTo(errorAddress);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("foo.com. bar.com.");
    MINFORecord minfo = new MINFORecord();
    minfo.rdataFromString(t, null);
    assertThat(minfo.getResponsibleAddress()).isEqualTo(Name.fromConstantString("foo.com."));
    assertThat(minfo.getErrorAddress()).isEqualTo(Name.fromConstantString("bar.com."));
  }
}

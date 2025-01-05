// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class MINFORecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_5arg() {
    Name respAddress = Name.fromConstantString("example.com.");
    Name errorAddress = Name.fromConstantString("error.com.");
    MINFORecord minfo = new MINFORecord(n, DClass.IN, 0, respAddress, errorAddress);
    assertEquals(respAddress, minfo.getResponsibleAddress());
    assertEquals(errorAddress, minfo.getErrorAddress());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("foo.com. bar.com.");
    MINFORecord minfo = new MINFORecord();
    minfo.rdataFromString(t, null);
    assertEquals(Name.fromConstantString("foo.com."), minfo.getResponsibleAddress());
    assertEquals(Name.fromConstantString("bar.com."), minfo.getErrorAddress());
  }
}

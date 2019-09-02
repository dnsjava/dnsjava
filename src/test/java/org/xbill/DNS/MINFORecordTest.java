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
    MINFORecord record = new MINFORecord(n, DClass.IN, 0, respAddress, errorAddress);
    assertEquals(respAddress, record.getResponsibleAddress());
    assertEquals(errorAddress, record.getErrorAddress());
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("foo.com. bar.com.");
    MINFORecord record = new MINFORecord();
    record.rdataFromString(t, null);
    assertEquals(Name.fromConstantString("foo.com."), record.getResponsibleAddress());
    assertEquals(Name.fromConstantString("bar.com."), record.getErrorAddress());
  }
}

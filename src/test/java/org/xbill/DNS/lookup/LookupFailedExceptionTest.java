// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

class LookupFailedExceptionTest {
  @Test
  void ctor_noNameAndType() {
    LookupFailedException exception = new LookupFailedException();
    assertNull(exception.getName());
    assertEquals(0, exception.getType());
  }

  @Test
  void ctor_withMessage() {
    LookupFailedException exception = new LookupFailedException("message");
    assertEquals("message", exception.getMessage());
    assertNull(exception.getName());
    assertEquals(0, exception.getType());
  }

  @Test
  void ctor_withNameAndType() {
    Name name = Name.fromConstantString("a.b.");
    int type = Type.A;
    LookupFailedException exception = new LookupFailedException(name, type);
    assertEquals(name, exception.getName());
    assertEquals(type, exception.getType());
  }
}

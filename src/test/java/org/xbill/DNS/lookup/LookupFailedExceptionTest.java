// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

class LookupFailedExceptionTest {
  @Test
  void ctor_noNameAndType() {
    LookupFailedException exception = new LookupFailedException();
    assertThat(exception.getName()).isNull();
    assertThat(exception.getType()).isZero();
  }

  @Test
  void ctor_withMessage() {
    LookupFailedException exception = new LookupFailedException("message");
    assertThat(exception.getMessage()).isEqualTo("message");
    assertThat(exception.getName()).isNull();
    assertThat(exception.getType()).isZero();
  }

  @Test
  void ctor_withNameAndType() {
    Name name = Name.fromConstantString("a.b.");
    int type = Type.A;
    LookupFailedException exception = new LookupFailedException(name, type);
    assertThat(exception.getName()).isEqualTo(name);
    assertThat(exception.getType()).isEqualTo(type);
  }
}

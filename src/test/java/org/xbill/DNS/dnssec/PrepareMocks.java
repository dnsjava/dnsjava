// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(value = RetentionPolicy.RUNTIME)
@Target(value = {ElementType.METHOD})
public @interface PrepareMocks {
  String value();
}

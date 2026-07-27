// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JnamedToolTest {
  private final PrintStream originalOut = System.out;
  private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();

  @BeforeEach
  void setUp() {
    System.setOut(new PrintStream(outContent));
  }

  @AfterEach
  void tearDown() {
    System.setOut(originalOut);
  }

  @Test
  void testAddrport() throws Exception {
    Method addrportMethod =
        jnamed.class.getDeclaredMethod("addrport", InetAddress.class, int.class);
    addrportMethod.setAccessible(true);

    InetAddress addr = InetAddress.getByName("127.0.0.1");
    String result = (String) addrportMethod.invoke(null, addr, 53);
    assertEquals("127.0.0.1#53", result);
  }
}

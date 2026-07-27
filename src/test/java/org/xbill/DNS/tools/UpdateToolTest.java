package org.xbill.DNS.tools;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.Name;
import org.xbill.DNS.Tokenizer;

class UpdateToolTest {

  @Test
  void testDoAssert() throws Exception {
    String input = "name example.com. type A\n";
    InputStream is = new ByteArrayInputStream(input.getBytes());
    update u = new update(is);

    // doAssert is protected, so use reflection
    Method doAssertMethod = update.class.getDeclaredMethod("doAssert", Tokenizer.class);
    doAssertMethod.setAccessible(true);

    Tokenizer st = new Tokenizer("name example.com. type A");
    Object result = doAssertMethod.invoke(u, st);
    assertNotNull(result);
  }

  @Test
  void testHelp() throws Exception {
    // help is protected
    update u = new update(new ByteArrayInputStream(new byte[0]));
    Method helpMethod = update.class.getDeclaredMethod("help", String.class);
    helpMethod.setAccessible(true);

    // This should not throw exception
    helpMethod.invoke(u, "add");
    helpMethod.invoke(u, (String) null);
  }
}

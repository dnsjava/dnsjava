package org.xbill.DNS.io;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.File;
import java.time.Duration;


public class AbstractSocksTest {
  static final ComposeContainer environment = new ComposeContainer(
    new File("src/test/resources/compose/compose.yml")
  )
  .withBuild(true)
  .waitingFor("dante-socks5", Wait.forHealthcheck());

  @Test
  public void setup() {
    environment.start();
    System.out.println("Container started");
    System.out.println("Container ready");
    environment.stop();
  }
}

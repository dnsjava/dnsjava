package org.xbill.DNS.io;

import org.testcontainers.containers.GenericContainer;

public class AbstractSocksTest {

  public static final GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:6-alpine"))
    .withExposedPorts(6379);

  static {
    redis.start();
  }

}

// SPDX-License-Identifier: BSD-3-Clause
package sun.net.spi.nameservice;

public interface NameServiceDescriptor {
  NameService createNameService() throws Exception;

  String getProviderName();

  String getType();
}

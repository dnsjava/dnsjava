// SPDX-License-Identifier: BSD-3-Clause
package android.net;

import java.net.InetAddress;
import java.util.List;

public class LinkProperties {
  public List<InetAddress> getDnsServers() {
    throw new UnsupportedOperationException();
  }

  public String getDomains() {
    throw new UnsupportedOperationException();
  }
}

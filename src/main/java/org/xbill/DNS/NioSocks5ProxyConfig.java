// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.net.InetSocketAddress;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NioSocks5ProxyConfig {
  private InetSocketAddress proxyAddress;
  private AuthMethod authMethod;
  private String socks5User;
  private String socks5Password;

  public enum AuthMethod {
    NONE,
    GSSAPI,
    USER_PASS
  }

  public NioSocks5ProxyConfig(InetSocketAddress proxyAddress) {
    this(proxyAddress, null, null);
    authMethod = AuthMethod.NONE;
  }

  public NioSocks5ProxyConfig(
      InetSocketAddress proxyAddress, String socks5User, String socks5Password) {
    this.proxyAddress = proxyAddress;
    this.socks5User = socks5User;
    this.socks5Password = socks5Password;
    authMethod = AuthMethod.USER_PASS;
  }

  //  public Socks5ProxyConfig(InetSocketAddress proxyAddress, GSSCredential gssCredential) {
  //    this(proxyAddress, null, null, gssCredential);
  //  }
}

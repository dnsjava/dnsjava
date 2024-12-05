package org.xbill.DNS;

import lombok.Getter;
import lombok.Setter;

import java.net.InetSocketAddress;

@Getter
@Setter
public class Socks5ProxyConfig {
  private InetSocketAddress proxyAddress;
  private AuthMethod authMethod;
  private String socks5User;
  private String socks5Password;

  public enum AuthMethod {
    NONE,
    GSSAPI,
    USER_PASS
  }

  public Socks5ProxyConfig(InetSocketAddress proxyAddress) {
    this(proxyAddress, null, null);
    authMethod = AuthMethod.NONE;
  }

  public Socks5ProxyConfig(InetSocketAddress proxyAddress, String socks5User, String socks5Password) {
    this.proxyAddress = proxyAddress;
    this.socks5User = socks5User;
    this.socks5Password = socks5Password;
    authMethod = AuthMethod.USER_PASS;
  }

//  public Socks5ProxyConfig(InetSocketAddress proxyAddress, GSSCredential gssCredential) {
//    this(proxyAddress, null, null, gssCredential);
//  }
}

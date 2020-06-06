// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import static org.xbill.DNS.config.IPHlpAPI.AF_UNSPEC;
import static org.xbill.DNS.config.IPHlpAPI.GAA_FLAG_SKIP_ANYCAST;
import static org.xbill.DNS.config.IPHlpAPI.GAA_FLAG_SKIP_FRIENDLY_NAME;
import static org.xbill.DNS.config.IPHlpAPI.GAA_FLAG_SKIP_MULTICAST;
import static org.xbill.DNS.config.IPHlpAPI.GAA_FLAG_SKIP_UNICAST;
import static org.xbill.DNS.config.IPHlpAPI.INSTANCE;
import static org.xbill.DNS.config.IPHlpAPI.IP_ADAPTER_ADDRESSES_LH;
import static org.xbill.DNS.config.IPHlpAPI.IP_ADAPTER_DNS_SERVER_ADDRESS_XP;
import static org.xbill.DNS.config.IPHlpAPI.IP_ADAPTER_DNS_SUFFIX;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.Name;
import org.xbill.DNS.SimpleResolver;

/**
 * Resolver config provider for Windows. It reads the nameservers and search path by calling the API
 * <a
 * href="https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses">GetAdaptersAddresses</a>.
 * This class requires the <a href="https://github.com/java-native-access/jna">JNA library</a> on
 * the classpath.
 */
@Slf4j
public class WindowsResolverConfigProvider implements ResolverConfigProvider {
  private InnerWindowsResolverConfigProvider inner;

  public WindowsResolverConfigProvider() {
    if (System.getProperty("os.name").contains("Windows")) {
      try {
        inner = new InnerWindowsResolverConfigProvider();
      } catch (NoClassDefFoundError e) {
        log.debug("JNA not available");
      }
    }
  }

  @Slf4j
  private static final class InnerWindowsResolverConfigProvider extends BaseResolverConfigProvider {
    static {
      log.debug(
          "Checking for JNA classes: {} and {}",
          Memory.class.getName(),
          Win32Exception.class.getName());
    }

    public void initialize() throws InitializationException {
      // The recommended method of calling the GetAdaptersAddresses function is to pre-allocate a
      // 15KB working buffer
      Memory buffer = new Memory(15 * 1024);
      IntByReference size = new IntByReference(0);
      int flags =
          GAA_FLAG_SKIP_UNICAST
              | GAA_FLAG_SKIP_ANYCAST
              | GAA_FLAG_SKIP_MULTICAST
              | GAA_FLAG_SKIP_FRIENDLY_NAME;
      int error = INSTANCE.GetAdaptersAddresses(AF_UNSPEC, flags, Pointer.NULL, buffer, size);
      if (error == WinError.ERROR_BUFFER_OVERFLOW) {
        buffer = new Memory(size.getValue());
        error = INSTANCE.GetAdaptersAddresses(AF_UNSPEC, flags, Pointer.NULL, buffer, size);
        if (error != WinError.ERROR_SUCCESS) {
          throw new InitializationException(new Win32Exception(error));
        }
      }

      IP_ADAPTER_ADDRESSES_LH result = new IP_ADAPTER_ADDRESSES_LH(buffer);
      do {
        // only interfaces with IfOperStatusUp
        if (result.OperStatus == 1) {
          IP_ADAPTER_DNS_SERVER_ADDRESS_XP dns = result.FirstDnsServerAddress;
          while (dns != null) {
            InetAddress address;
            try {
              address = dns.Address.toAddress();
              if (address instanceof Inet4Address || !address.isSiteLocalAddress()) {
                addNameserver(new InetSocketAddress(address, SimpleResolver.DEFAULT_PORT));
              } else {
                log.debug(
                    "Skipped site-local IPv6 server address {} on adapter index {}",
                    address,
                    result.IfIndex);
              }
            } catch (UnknownHostException e) {
              log.warn("Invalid nameserver address on adapter index {}", result.IfIndex, e);
            }

            dns = dns.Next;
          }

          addSearchPath(result.DnsSuffix.toString());
          IP_ADAPTER_DNS_SUFFIX suffix = result.FirstDnsSuffix;
          while (suffix != null) {
            addSearchPath(String.valueOf(suffix._String));
            suffix = suffix.Next;
          }
        }

        result = result.Next;
      } while (result != null);
    }
  }

  @Override
  public void initialize() throws InitializationException {
    inner.initialize();
  }

  @Override
  public List<InetSocketAddress> servers() {
    return inner.servers();
  }

  @Override
  public List<Name> searchPaths() {
    return inner.searchPaths();
  }

  @Override
  public boolean isEnabled() {
    return inner != null;
  }
}

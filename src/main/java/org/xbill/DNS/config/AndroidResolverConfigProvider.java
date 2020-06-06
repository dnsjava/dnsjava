// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Build;
import android.os.SystemProperties;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.ResolverConfig;
import org.xbill.DNS.SimpleResolver;

/**
 * Resolver config provider for Android. Contrary to all other providers, this provider needs a
 * context to operate on which must be set by calling {@link #setContext(Context)}.
 *
 * <p>If you are developing for Android, consider implementing your own {@link
 * ResolverConfigProvider} that listens to network callbacks and properly refreshes on link changes.
 * Something you need to do anyway to call {@link ResolverConfig#refresh()} otherwise it is pretty
 * much guaranteed to have outdated servers sooner or later.
 */
@Slf4j
public class AndroidResolverConfigProvider extends BaseResolverConfigProvider {
  private static Context context = null;

  /** Gets the current configuration */
  public static void setContext(Context ctx) {
    context = ctx;
  }

  @Override
  public void initialize() throws InitializationException {
    // This originally looked for all lines containing .dns; but
    // http://code.google.com/p/android/issues/detail?id=2207#c73 indicates
    // that net.dns* should always be the active nameservers, so we use those.
    // Starting with Android 8 (API 26), the net.dns[1234] properties are no longer available:
    // https://developer.android.com/about/versions/oreo/android-8.0-changes.html#o-pri
    if (Build.VERSION.SDK_INT >= 26) {
      initializeApi26Nameservers();
    } else {
      initializeNameservers();
    }
  }

  private void initializeNameservers() {
    for (int i = 1; i <= 4; i++) {
      String server = SystemProperties.get("net.dns" + i);
      if (server != null && !server.isEmpty()) {
        addNameserver(new InetSocketAddress(server, SimpleResolver.DEFAULT_PORT));
      }
    }
  }

  private void initializeApi26Nameservers() throws InitializationException {
    if (context == null) {
      throw new InitializationException("Context must be initialized by calling setContext");
    }

    ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
    Network network = cm.getActiveNetwork();
    if (network == null) {
      // if the device is offline, there's no active network
      return;
    }

    LinkProperties lp = cm.getLinkProperties(network);
    if (lp == null) {
      // can be null for an unknown network, which may happen if networks change
      return;
    }

    for (InetAddress address : lp.getDnsServers()) {
      addNameserver(new InetSocketAddress(address, SimpleResolver.DEFAULT_PORT));
    }

    parseSearchPathList(lp.getDomains(), ",");
  }

  @Override
  public boolean isEnabled() {
    return System.getProperty("java.vendor").contains("Android");
  }
}

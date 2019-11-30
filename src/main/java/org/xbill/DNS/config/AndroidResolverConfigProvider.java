// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.ResolverConfig;
import org.xbill.DNS.SimpleResolver;

/**
 * Resolver config provider for Android. Contrary to all other providers, this provider needs a
 * context to operate on which must be set by calling {@link #setContext(Object)}.
 *
 * <p>If you are developing for Android, consider implementing your own {@link
 * ResolverConfigProvider} that listens to network callbacks and properly refreshes on link changes.
 * Something you need to do anyway to call {@link ResolverConfig#refresh()} otherwise it is pretty
 * much guaranteed to have outdated servers sooner or later.
 */
@Slf4j
public class AndroidResolverConfigProvider extends BaseResolverConfigProvider {
  private static Object context = null;

  /** Gets the current configuration */
  public static void setContext(Object ctx) {
    context = ctx;
  }

  @Override
  public void initialize() throws InitializationException {
    // This originally looked for all lines containing .dns; but
    // http://code.google.com/p/android/issues/detail?id=2207#c73 indicates
    // that net.dns* should always be the active nameservers, so we use those.
    // Starting with Android 8 (API 26), the net.dns[1234] properties are no longer available:
    // https://developer.android.com/about/versions/oreo/android-8.0-changes.html#o-pri
    try {
      Class<?> Version = Class.forName("android.os.Build$VERSION");
      Field SDK_INT = Version.getField("SDK_INT");

      if (SDK_INT.getInt(null) >= 26) {
        initializeApi26Nameservers();
      } else {
        initializeNameservers();
      }
    } catch (NoSuchMethodException
        | InvocationTargetException
        | NoSuchFieldException
        | IllegalAccessException
        | ClassNotFoundException e) {
      throw new InitializationException(e);
    }
  }

  private void initializeNameservers()
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
          InvocationTargetException {
    Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
    Method method = systemPropertiesClass.getMethod("get", String.class);
    for (int i = 1; i <= 4; i++) {
      String server = (String) method.invoke(null, "net.dns" + i);
      if (server != null && !server.isEmpty()) {
        nameservers.add(new InetSocketAddress(server, SimpleResolver.DEFAULT_PORT));
      }
    }
  }

  private void initializeApi26Nameservers()
      throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
          InvocationTargetException, InitializationException {
    if (context == null) {
      throw new InitializationException("Context must be initialized by calling setContext");
    }

    Class<?> contextClass = Class.forName("android.content.Context");
    Method getSystemService = contextClass.getDeclaredMethod("getSystemService", String.class);
    Object cm = getSystemService.invoke(context, "connectivity");

    Class<?> connectivityManagerClass = Class.forName("android.net.ConnectivityManager");
    Method getActiveNetwork = connectivityManagerClass.getDeclaredMethod("getActiveNetwork");
    Object network = getActiveNetwork.invoke(cm);
    if (network == null) {
      // if the device is offline, there's no active network
      return;
    }

    Class<?> networkClass = Class.forName("android.net.Network");
    Method getLinkProperties =
        connectivityManagerClass.getDeclaredMethod("getLinkProperties", networkClass);
    Object lp = getLinkProperties.invoke(cm, network);
    if (lp == null) {
      // can be null for an unknown network, which may happen if networks change
      return;
    }

    Class<?> linkPropertiesClass = Class.forName("android.net.LinkProperties");
    Method getDnsServers = linkPropertiesClass.getDeclaredMethod("getDnsServers");
    @SuppressWarnings("unchecked")
    List<InetAddress> addresses = (List<InetAddress>) getDnsServers.invoke(lp);

    for (InetAddress address : addresses) {
      addNameserver(new InetSocketAddress(address, SimpleResolver.DEFAULT_PORT));
    }

    Method getDomains = linkPropertiesClass.getDeclaredMethod("getDomains");
    parseSearchPathList((String) getDomains.invoke(lp), ",");
  }

  @Override
  public boolean isEnabled() {
    return System.getProperty("java.vendor").contains("Android");
  }
}

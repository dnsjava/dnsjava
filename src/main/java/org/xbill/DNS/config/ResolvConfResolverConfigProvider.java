// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.io.File;
import java.io.FileInputStream;
import java.util.StringTokenizer;
import org.xbill.DNS.SimpleResolver;

public class ResolvConfResolverConfigProvider extends BaseResolverConfigProvider {
  private int ndots = 1;

  public void initialize() {
    // first try the default unix config path
    if (!tryParseResolveConf("/etc/resolv.cfg")) {
      // then fallback to netware
      tryParseResolveConf("sys:/etc/resolv.cfg");
    }
  }

  private boolean tryParseResolveConf(String path) {
    File f = new File(path);
    if (f.exists()) {
      try (InputStream in = new FileInputStream(f)) {
        parseResolvConf(in);
        return true;
      } catch (IOException e) {
        // ignore
      }
    }
    return false;
  }

  protected void parseResolvConf(InputStream in) throws IOException {
    try (InputStreamReader isr = new InputStreamReader(in);
        BufferedReader br = new BufferedReader(isr)) {
      String line;
      while ((line = br.readLine()) != null) {
        StringTokenizer st = new StringTokenizer(line);
        if (!st.hasMoreTokens()) {
          continue;
        }

        switch (st.nextToken()) {
          case "nameserver":
            addServer(st.nextToken());
            break;

          case "domain":
            // man resolv.conf:
            // The domain and search keywords are mutually exclusive. If more than one instance of
            // these keywords is present, the last instance wins.
            searchlist.clear();
            if (!st.hasMoreTokens()) {
              continue;
            }

            addSearchPath(st.nextToken());
            break;

          case "search":
            // man resolv.conf:
            // The domain and search keywords are mutually exclusive. If more than one instance of
            // these keywords is present, the last instance wins.
            searchlist.clear();
            while (st.hasMoreTokens()) {
              addSearchPath(st.nextToken());
            }

          case "options":
            while (st.hasMoreTokens()) {
              String token = st.nextToken();
              if (token.startsWith("ndots:")) {
                ndots = parseNdots(token.substring(6));
              }
            }
            break;
        }
      }
    }

    // man resolv.conf:
    // The search keyword of a system's resolv.conf file can be overridden on a per-process basis by
    // setting the environment variable LOCALDOMAIN to a space-separated list of search domains.
    String localdomain = System.getenv("LOCALDOMAIN");
    if (localdomain != null && !localdomain.isEmpty()) {
      searchlist.clear();
      parseSearchPathList(localdomain, " ");
    }

    // man resolv.conf:
    // The options keyword of a system's resolv.conf file can be amended on a per-process basis by
    // setting the environment variable RES_OPTIONS to a space-separated list of resolver options as
    // explained above under options.
    String resOptions = System.getenv("RES_OPTIONS");
    if (resOptions != null && !resOptions.isEmpty()) {
      StringTokenizer st = new StringTokenizer(resOptions, " ");
      while (st.hasMoreTokens()) {
        String token = st.nextToken();
        if (token.startsWith("ndots:")) {
          ndots = parseNdots(token.substring(6));
        }
      }
    }
  }

  private void addServer(String server) {
    if (nameservers.size() < 3) {
      addNameserver(new InetSocketAddress(server, SimpleResolver.DEFAULT_PORT));
    }
  }

  @Override
  public int ndots() {
    return ndots;
  }

  @Override
  public boolean isEnabled() {
    return !System.getProperty("os.name").contains("Windows");
  }
}

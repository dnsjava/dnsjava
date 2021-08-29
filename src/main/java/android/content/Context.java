// SPDX-License-Identifier: BSD-2-Clause
package android.content;

import android.net.ConnectivityManager;

public class Context {
  public ConnectivityManager getSystemService(Class<ConnectivityManager> connectivityManagerClass) {
    throw new UnsupportedOperationException("dummy class, for compilation only");
  }
}

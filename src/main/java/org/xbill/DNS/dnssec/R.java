// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Utility class to retrieve messages from {@link ResourceBundle}s.
 *
 * @since 3.5
 */
public final class R {
  private static ResourceBundle rb;
  private static boolean useNeutral;

  private R() {}

  /**
   * Programmatically set the ResourceBundle to be used.
   *
   * @param resourceBundle the bundle to be used.
   */
  public static void setBundle(ResourceBundle resourceBundle) {
    R.rb = resourceBundle;
  }

  /**
   * If set to {@code true}, messages will not be obtained from resource bundles but formatted as
   * {@code key:param1:...:paramN}.
   *
   * @param useNeutral {@code true} to use neutral messages, {@code false} otherwise
   */
  public static void setUseNeutralMessages(boolean useNeutral) {
    R.useNeutral = useNeutral;
  }

  /**
   * Gets a translated message.
   *
   * @param key The message key to retrieve.
   * @param values The values that fill placeholders in the message.
   * @return The formatted message.
   */
  public static String get(String key, Object... values) {
    if (useNeutral) {
      return getNeutral(key, values);
    }

    try {
      if (R.rb == null) {
        rb = ResourceBundle.getBundle("messages");
      }

      return MessageFormat.format(rb.getString(key), values);
    } catch (MissingResourceException e) {
      return getNeutral(key, values);
    }
  }

  private static String getNeutral(String key, Object[] values) {
    StringBuilder sb = new StringBuilder(key);
    for (Object val : values) {
      sb.append(":");
      sb.append(val);
    }

    return sb.toString();
  }
}

// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Routines for converting time values to and from YYYYMMDDHHMMSS format.
 *
 * @author Brian Wellington
 */
final class FormattedTime {
  private static final DateTimeFormatter DEFAULT_FORMAT =
      DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

  private FormattedTime() {}

  /**
   * Converts a Date into a formatted string.
   *
   * @param date The Instant to convert.
   * @return The formatted string.
   */
  public static String format(Instant date) {
    return DEFAULT_FORMAT.format(date);
  }

  /**
   * Parses a formatted time string into an Instant.
   *
   * @param s The string, in the form YYYYMMDDHHMMSS or seconds since epoch (1 January 1970 00:00:00
   *     UTC).
   * @return The Instant object.
   * @throws DateTimeParseException The string was invalid.
   */
  public static Instant parse(String s) throws DateTimeParseException {
    // rfc4034#section-3.2
    if (s.length() == 14) {
      return DEFAULT_FORMAT.parse(s, Instant::from);
    } else if (s.length() <= 10) {
      return Instant.ofEpochSecond(Long.parseLong(s));
    }
    throw new DateTimeParseException("Invalid time encoding: ", s, 0);
  }
}

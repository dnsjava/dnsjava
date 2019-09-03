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
   * @param s The string, in the form YYYYMMDDHHMMSS.
   * @return The Instant object.
   * @throws DateTimeParseException The string was invalid.
   */
  public static Instant parse(String s) throws DateTimeParseException {
    return DEFAULT_FORMAT.parse(s, Instant::from);
  }
}

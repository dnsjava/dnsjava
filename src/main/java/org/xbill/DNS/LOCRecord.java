// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.text.DecimalFormat;
import java.text.NumberFormat;

/**
 * Location - describes the physical location of hosts, networks, subnets.
 *
 * @author Brian Wellington
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc1876">RFC 1876: A Means for Expressing
 *     Location Information in the Domain Name System</a>
 */
public class LOCRecord extends Record {
  private static final NumberFormat w2;
  private static final NumberFormat w3;
  private long size;
  private long hPrecision;
  private long vPrecision;
  private long latitude;
  private long longitude;
  private long altitude;

  static {
    w2 = new DecimalFormat();
    w2.setMinimumIntegerDigits(2);

    w3 = new DecimalFormat();
    w3.setMinimumIntegerDigits(3);
  }

  LOCRecord() {}

  /**
   * Creates an LOC Record from the given data.
   *
   * <p>Note that the RFC specifies the size and precisions in [cm], while this class uses [m].
   *
   * @param latitude The latitude of the center of the sphere.
   * @param longitude The longitude of the center of the sphere.
   * @param altitude The altitude of the center of the sphere, in [m].
   * @param size The diameter of a sphere enclosing the described entity, in [m].
   * @param hPrecision The horizontal precision of the data, in [m].
   * @param vPrecision The vertical precision of the data, in [m].
   */
  public LOCRecord(
      Name name,
      int dclass,
      long ttl,
      double latitude,
      double longitude,
      double altitude,
      double size,
      double hPrecision,
      double vPrecision) {
    super(name, Type.LOC, dclass, ttl);
    if (size < 0 || size > 90000000 || Double.isNaN(size)) {
      throw new IllegalArgumentException("size must be > 0 and < 90000000");
    }
    if (hPrecision < 0 || hPrecision > 9e7 || Double.isNaN(hPrecision)) {
      throw new IllegalArgumentException("size must be > 0");
    }
    if (vPrecision < 0 || vPrecision > 9e7 || Double.isNaN(vPrecision)) {
      throw new IllegalArgumentException("size must be > 0");
    }
    if (latitude < -90.0 || latitude > 90.0 || Double.isNaN(latitude)) {
      throw new IllegalArgumentException("latitude must be between -90 and 90");
    }
    if (longitude < -180.0 || longitude > 180.0 || Double.isNaN(longitude)) {
      throw new IllegalArgumentException("longitude must be between -180 and 180");
    }
    if (altitude < -100000.0 || altitude > 42849672.95 || Double.isNaN(altitude)) {
      throw new IllegalArgumentException("altitude must be between -100000 and 42849672.95");
    }

    this.latitude = (long) (latitude * 3600 * 1000 + (1L << 31));
    this.longitude = (long) (longitude * 3600 * 1000 + (1L << 31));
    this.altitude = (long) ((altitude + 100000) * 100);
    this.size = (long) (size * 100);
    this.hPrecision = (long) (hPrecision * 100);
    this.vPrecision = (long) (vPrecision * 100);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    int version = in.readU8();
    if (version != 0) {
      throw new WireParseException("Invalid LOC version");
    }

    size = parseLOCformat(in.readU8());
    hPrecision = parseLOCformat(in.readU8());
    vPrecision = parseLOCformat(in.readU8());
    latitude = in.readU32();
    longitude = in.readU32();
    altitude = in.readU32();
  }

  private long parsePosition(Tokenizer st, String type, int max) throws IOException {
    boolean isLatitude = type.equals("latitude");

    int deg = st.getUInt16();
    if (deg > 180 || (deg > 90 && isLatitude)) {
      throw st.exception("Invalid LOC " + type + " degrees");
    }

    int minute;
    try {
      String s = st.getString();
      if (!isLatLongChar(s)) {
        minute = Integer.parseInt(s);
        if (minute < 0 || minute > 59 || (minute > 0 && deg == max)) {
          throw st.exception("Invalid LOC " + type + " minutes");
        }
      } else {
        minute = 0;
        st.unget();
      }
    } catch (NumberFormatException e) {
      throw st.exception("Invalid LOC " + type + " minutes", e);
    }

    double sec;
    try {
      String s = st.getString();
      if (!isLatLongChar(s)) {
        if (s.equalsIgnoreCase("nan")) {
          throw st.exception("Invalid LOC " + type);
        }
        sec = Double.parseDouble(s);
        if (sec < 0 || sec >= 60 || (sec > 0 && deg == max)) {
          throw st.exception("Invalid LOC " + type + " seconds");
        }
      } else {
        sec = 0;
        st.unget();
      }
    } catch (NumberFormatException e) {
      throw st.exception("Invalid LOC " + type + " seconds", e);
    }

    long value = Math.round(1000 * (sec + 60L * (minute + 60L * deg)));

    String s = st.getString();
    if (s.length() != 1) {
      throw st.exception("Invalid LOC " + type);
    }

    char c = Character.toUpperCase(s.charAt(0));
    if ((isLatitude && c == 'S') || (!isLatitude && c == 'W')) {
      value = -value;
    } else if ((isLatitude && c != 'N') || (!isLatitude && c != 'E')) {
      throw st.exception("Invalid LOC " + type);
    }

    value += 1L << 31;

    return value;
  }

  private static boolean isLatLongChar(String s) {
    return s.equalsIgnoreCase("N")
        || s.equalsIgnoreCase("S")
        || s.equalsIgnoreCase("E")
        || s.equalsIgnoreCase("W");
  }

  private long parseDouble(
      Tokenizer st, String type, boolean required, long min, long max, long defaultValue)
      throws IOException {
    Tokenizer.Token token = st.get();
    if (token.isEOL()) {
      if (required) {
        throw st.exception("Invalid LOC " + type);
      }
      st.unget();
      return defaultValue;
    }
    String s = token.value();
    if (s.length() > 1 && s.charAt(s.length() - 1) == 'm') {
      s = s.substring(0, s.length() - 1);
    }
    try {
      if (s.equalsIgnoreCase("nan")) {
        throw st.exception("Invalid LOC " + type);
      }
      long value = (long) (100 * Double.parseDouble(s));
      if (value < min || value > max) {
        throw st.exception("Invalid LOC " + type);
      }
      return value;
    } catch (NumberFormatException e) {
      throw st.exception("Invalid LOC " + type);
    }
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    latitude = parsePosition(st, "latitude", 90);
    longitude = parsePosition(st, "longitude", 180);
    altitude = parseDouble(st, "altitude", true, -10000000, 4284967295L, 0) + 10000000;
    size = parseDouble(st, "size", false, 0, 9000000000L, 100);
    hPrecision = parseDouble(st, "horizontal precision", false, 0, 9000000000L, 1000000);
    vPrecision = parseDouble(st, "vertical precision", false, 0, 9000000000L, 1000);
  }

  private void renderFixedPoint(
      StringBuilder sb, NumberFormat formatter, long value, long divisor) {
    if (value < 0) {
      // Print the sign of the integral part before taking the absolute value:
      // -1/100 is 0, so a negative value below one divisor would otherwise be
      // rendered without its sign.
      sb.append('-');
      value = -value;
    }
    sb.append(value / divisor);
    value %= divisor;
    if (value != 0) {
      sb.append(".");
      sb.append(formatter.format(value));
    }
  }

  private void positionToString(StringBuilder sb, long value, char pos, char neg) {
    char direction;

    long temp = value - (1L << 31);
    if (temp < 0) {
      temp = -temp;
      direction = neg;
    } else {
      direction = pos;
    }

    sb.append(w2.format(temp / (3600 * 1000))); /* degrees */
    sb.append(' ');

    temp = temp % (3600 * 1000);
    sb.append(w2.format(temp / (60 * 1000))); /* minutes */
    sb.append(' ');

    temp = temp % (60 * 1000);
    renderFixedPoint(sb, w3, temp, 1000); /* seconds */
    sb.append(' ');

    sb.append(direction);
  }

  /** Convert to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();

    /* Latitude */
    positionToString(sb, latitude, 'N', 'S');
    sb.append(' ');

    /* Latitude */
    positionToString(sb, longitude, 'E', 'W');
    sb.append(' ');

    /* Altitude */
    renderFixedPoint(sb, w2, altitude - 10000000, 100);
    sb.append("m ");

    /* Size */
    renderFixedPoint(sb, w2, size, 100);
    sb.append("m ");

    /* Horizontal precision */
    renderFixedPoint(sb, w2, hPrecision, 100);
    sb.append("m ");

    /* Vertical precision */
    renderFixedPoint(sb, w2, vPrecision, 100);
    sb.append("m");

    return sb.toString();
  }

  /** Returns the latitude */
  public double getLatitude() {
    return (double) (latitude - (1L << 31)) / (3600 * 1000);
  }

  /** Returns the longitude */
  public double getLongitude() {
    return (double) (longitude - (1L << 31)) / (3600 * 1000);
  }

  /** Returns the altitude */
  public double getAltitude() {
    return (double) (altitude - 10000000) / 100;
  }

  /** Returns the diameter of the enclosing sphere in [m]. */
  public double getSize() {
    return (double) size / 100;
  }

  /** Returns the horizontal precision in [m]. */
  public double getHPrecision() {
    return (double) hPrecision / 100;
  }

  /** Returns the horizontal precision in [m]. */
  public double getVPrecision() {
    return (double) vPrecision / 100;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(0); /* version */
    out.writeU8(toLOCformat(size));
    out.writeU8(toLOCformat(hPrecision));
    out.writeU8(toLOCformat(vPrecision));
    out.writeU32(latitude);
    out.writeU32(longitude);
    out.writeU32(altitude);
  }

  private static long parseLOCformat(int b) throws WireParseException {
    long out = b >> 4;
    int exp = b & 0xF;
    if (out > 9 || exp > 9 || (out <= 0 && exp > 0)) {
      throw new WireParseException("Invalid LOC Encoding");
    }
    while (exp-- > 0) {
      out *= 10;
    }
    return out;
  }

  private int toLOCformat(long l) {
    byte exp = 0;
    while (l > 9) {
      exp++;
      l /= 10;
    }
    return (int) ((l << 4) + (exp & 0xFF));
  }
}

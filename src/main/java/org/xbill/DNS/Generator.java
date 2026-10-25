// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A representation of a $GENERATE statement in a master file.
 *
 * @author Brian Wellington
 */
public class Generator {

  /** The start of the range. */
  public long start;

  /** The end of the range. */
  public long end;

  /** The step value of the range. */
  public long step;

  /** The pattern to use for generating record names. */
  public final String namePattern;

  /** The type of the generated records. */
  public final int type;

  /** The class of the generated records. */
  public final int dclass;

  /** The ttl of the generated records. */
  public final long ttl;

  /** The pattern to use for generating record data. */
  public final String rdataPattern;

  /** The origin to append to relative names. */
  public final Name origin;

  private long current;

  /**
   * Indicates whether generation is supported for this type.
   *
   * @throws InvalidTypeException The type is out of range.
   */
  public static boolean supportedType(int type) {
    Type.check(type);
    return type == Type.PTR
        || type == Type.CNAME
        || type == Type.DNAME
        || type == Type.A
        || type == Type.AAAA
        || type == Type.NS;
  }

  /**
   * Creates a specification for generating records, as a $GENERATE statement in a master file.
   *
   * @param start The start of the range (inclusive).
   * @param end The end of the range (inclusive).
   * @param step The step value of the range.
   * @param namePattern The pattern to use for generating record names.
   * @param type The type of the generated records. The supported types are PTR, CNAME, DNAME, A,
   *     AAAA, and NS.
   * @param dclass The class of the generated records.
   * @param ttl The ttl of the generated records.
   * @param rdataPattern The pattern to use for generating record data.
   * @param origin The origin to append to relative names.
   * @throws IllegalArgumentException The range is invalid.
   * @throws IllegalArgumentException The type does not support generation.
   * @throws IllegalArgumentException The dclass is not a valid class.
   */
  public Generator(
      long start,
      long end,
      long step,
      String namePattern,
      int type,
      int dclass,
      long ttl,
      String rdataPattern,
      Name origin) {
    if (start < 0 || end < 0 || start > end || step <= 0) {
      throw new IllegalArgumentException("invalid range specification");
    }
    if (!supportedType(type)) {
      throw new IllegalArgumentException("unsupported type");
    }
    DClass.check(dclass);

    this.start = start;
    this.end = end;
    this.step = step;
    this.namePattern = namePattern;
    this.type = type;
    this.dclass = dclass;
    this.ttl = ttl;
    this.rdataPattern = rdataPattern;
    this.origin = origin;
    this.current = start;
  }

  private String substitute(String spec, long n, int maxLength) throws IOException {
    // Replace patterns of the format ${offset[,width[,base]]} or $, which is equivalent to '${0}'
    int sign = 1;
    long offset = 0;
    long width = 0;
    int radix = 10;
    int specPos = 0;
    boolean escaped = false;
    boolean dollar = false;
    boolean uppercase = false;

    StringBuilder sb = new StringBuilder(spec.length());
    for (int i = 0; i < spec.length(); i++) {
      char c = spec.charAt(i);
      if (c == '\\') {
        escaped = true;
      } else if (!escaped && !dollar && c == '$') {
        dollar = true;
      } else if (!escaped && c == '$') {
        // '$$' == literal '$' for compatibility with old versions of BIND
        dollar = false;
        sb.append(c);
      } else if (dollar && c == '{') {
        specPos = 1;
        sign = 1;
        offset = 0;
        width = 0;
        radix = 10;
        uppercase = false;
      } else if (dollar && specPos == 0) {
        sb.append(n);
        sb.append(c);
        dollar = false;
      } else if (specPos > 0) {
        if (c == '-' && specPos == 1) {
          sign = -1;
        } else if (c >= '0' && c <= '9') {
          if (specPos == 1) {
            offset *= 10;
            offset += c - '0';
          } else if (specPos == 2) {
            width *= 10;
            width += c - '0';
          }
        } else if (c == ',') {
          specPos++;
          if (specPos > 3) {
            throw new TextParseException("invalid spec, too many parts");
          }
        } else if (c == '}') {
          specPos = 0;
        } else if (c == 'x') {
          radix = 16;
        } else if (c == 'X') {
          radix = 16;
          uppercase = true;
        } else if (c == 'o' || c == 'O') {
          radix = 8;
        } else if (c == 'd' || c == 'D') {
          radix = 10;
        } else if (specPos == 1) {
          throw new TextParseException("invalid spec, unexpected character " + c + " for offset");
        } else if (specPos == 2) {
          throw new TextParseException("invalid spec, unexpected character " + c + " for width");
        } else {
          throw new TextParseException("invalid spec, unexpected character " + c + " for base");
        }

        if (specPos == 0) {
          offset *= sign;

          long value = n + offset;
          if (value < 0) {
            throw new TextParseException(
                "invalid offset expansion: negative value for $=" + n + ", offset=" + offset);
          }

          String number = Long.toString(value, radix);
          if (uppercase) {
            number = number.toUpperCase(Locale.ENGLISH);
          }

          if (width > number.length()) {
            long zeros = width - number.length();
            if (maxLength > -1 && zeros >= maxLength || zeros > Integer.MAX_VALUE) {
              throw new TextParseException("expansion exceeds max length");
            }

            while (zeros-- > 0) {
              sb.append('0');
            }
          }

          sb.append(number);
          dollar = false;
        }
      } else {
        escaped = false;
        sb.append(c);
      }
    }

    if (specPos != 0 || escaped) {
      throw new TextParseException("invalid spec, unexpected end of pattern");
    }

    // End of string, append the number
    if (dollar) {
      sb.append(n);
    }

    if (maxLength > -1 && sb.length() >= maxLength) {
      throw new TextParseException("expansion exceeds max length");
    }

    return sb.toString();
  }

  /**
   * Constructs and returns the next record in the expansion.
   *
   * @throws IOException The name or rdata was invalid after substitutions were performed.
   */
  public Record nextRecord() throws IOException {
    if (current > end) {
      return null;
    }
    String namestr = substitute(namePattern, current, Name.MAXNAME);
    Name name = Name.fromString(namestr, origin);
    String rdata = substitute(rdataPattern, current, -1);
    current += step;
    return Record.fromString(name, type, dclass, ttl, rdata, origin);
  }

  /**
   * Constructs and returns all records in the expansion.
   *
   * @throws IOException The name or rdata of a record was invalid after substitutions were
   *     performed.
   */
  public Record[] expand() throws IOException {
    List<Record> list = new ArrayList<>();
    for (long i = start; i <= end; i += step) {
      String namestr = substitute(namePattern, i, Name.MAXNAME);
      Name name = Name.fromString(namestr, origin);
      String rdata = substitute(rdataPattern, i, -1);
      list.add(Record.fromString(name, type, dclass, ttl, rdata, origin));
    }
    return list.toArray(new Record[0]);
  }

  /**
   * Converts the generate specification to a string containing the corresponding $GENERATE
   * statement.
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("$GENERATE ");
    sb.append(start).append("-").append(end);
    if (step > 1) {
      sb.append("/").append(step);
    }
    sb.append(" ");
    sb.append(namePattern).append(" ");
    sb.append(ttl).append(" ");
    if (dclass != DClass.IN || !Options.check("noPrintIN")) {
      sb.append(DClass.string(dclass)).append(" ");
    }
    sb.append(Type.string(type)).append(" ");
    sb.append(rdataPattern).append(" ");
    return sb.toString();
  }
}

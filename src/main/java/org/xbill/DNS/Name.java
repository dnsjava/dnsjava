// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;

/**
 * A representation of a domain name. It may either be absolute (fully qualified) or relative.
 *
 * @author Brian Wellington
 */
@Slf4j
public class Name implements Comparable<Name>, Serializable {

  private static final long serialVersionUID = -6036624806201621219L;

  private static final int LABEL_NORMAL = 0;
  private static final int LABEL_COMPRESSION = 0xC0;
  private static final int LABEL_MASK = 0xC0;

  /* The name data */
  private byte[] name;

  /* Effectively an 8 byte array, where the bytes store per-label offsets. */
  private long offsets;

  /* Precomputed hashcode. */
  private transient int hashcode;

  /* The number of labels in this name. */
  private int labels;

  private static final byte[] emptyLabel = new byte[] {(byte) 0};
  private static final byte[] wildLabel = new byte[] {(byte) 1, (byte) '*'};

  /** The root name */
  public static final Name root;

  /** The root name */
  public static final Name empty;

  /** The maximum length of a Name */
  private static final int MAXNAME = 255;

  /** The maximum length of a label a Name */
  private static final int MAXLABEL = 63;

  /** The maximum number of cached offsets, the first offset (always zero) is not stored. */
  private static final int MAXOFFSETS = 9;

  /* Used to efficiently convert bytes to lowercase */
  private static final byte[] lowercase = new byte[256];

  /* Used in wildcard names. */
  private static final Name wild;

  static {
    for (int i = 0; i < lowercase.length; i++) {
      if (i < 'A' || i > 'Z') {
        lowercase[i] = (byte) i;
      } else {
        lowercase[i] = (byte) (i - 'A' + 'a');
      }
    }
    root = new Name();
    root.name = emptyLabel;
    root.labels = 1;
    empty = new Name();
    empty.name = new byte[0];
    wild = new Name();
    wild.name = wildLabel;
    wild.labels = 1;
  }

  private Name() {}

  private void setOffset(int n, int offset) {
    if (n == 0 || n >= MAXOFFSETS) {
      return;
    }
    int shift = 8 * (n - 1);
    offsets &= ~(0xFFL << shift);
    offsets |= (long) offset << shift;
  }

  private int offset(int n) {
    if (n == 0) {
      return 0;
    }
    if (n < 1 || n >= labels) {
      throw new IllegalArgumentException("label out of range");
    }
    if (n < MAXOFFSETS) {
      int shift = 8 * (n - 1);
      return (int) (offsets >>> shift) & 0xFF;
    } else {
      int pos = (int) (offsets >>> (8 * (MAXOFFSETS - 2))) & 0xFF;
      for (int i = MAXOFFSETS - 1; i < n; i++) {
        pos += name[pos] + 1;
      }
      return pos;
    }
  }

  private static void copy(Name src, Name dst) {
    dst.name = src.name;
    dst.offsets = src.offsets;
    dst.labels = src.labels;
  }

  private void append(byte[] array, int arrayOffset, int numLabels) throws NameTooLongException {
    int length = name == null ? 0 : name.length;
    int appendLength = 0;
    for (int i = 0, pos = arrayOffset; i < numLabels; i++) {
      // add one byte for the label length
      int len = array[pos] + 1;
      pos += len;
      appendLength += len;
    }
    int newlength = length + appendLength;
    if (newlength > MAXNAME) {
      throw new NameTooLongException();
    }
    byte[] newname;
    if (name != null) {
      newname = Arrays.copyOf(name, newlength);
    } else {
      newname = new byte[newlength];
    }
    System.arraycopy(array, arrayOffset, newname, length, appendLength);
    name = newname;
    for (int i = 0, pos = length; i < numLabels && i < MAXOFFSETS; i++) {
      setOffset(labels + i, pos);
      pos += newname[pos] + 1;
    }
    labels += numLabels;
  }

  private void append(char[] label, int len) throws NameTooLongException {
    int destPos = prepareAppend(len);
    for (int i = 0; i < len; i++) {
      name[destPos + i] = (byte) label[i];
    }
  }

  private int prepareAppend(int len) throws NameTooLongException {
    int length = name == null ? 0 : name.length;
    // add one byte for the label length
    int newlength = length + 1 + len;
    if (newlength > MAXNAME) {
      throw new NameTooLongException();
    }
    byte[] newname;
    if (name != null) {
      newname = Arrays.copyOf(name, newlength);
    } else {
      newname = new byte[newlength];
    }
    newname[length] = (byte) len;
    name = newname;
    setOffset(labels, length);
    labels++;
    return length + 1;
  }

  private void appendFromString(String fullName, char[] label, int length)
      throws TextParseException {
    try {
      append(label, length);
    } catch (NameTooLongException e) {
      throw new TextParseException(fullName, "Name too long", e);
    }
  }

  private void appendFromString(String fullName, byte[] label, int n) throws TextParseException {
    try {
      append(label, 0, n);
    } catch (NameTooLongException e) {
      throw new TextParseException(fullName, "Name too long");
    }
  }

  /**
   * Create a new name from a string and an origin. This does not automatically make the name
   * absolute; it will be absolute if it has a trailing dot or an absolute origin is appended.
   *
   * @param s The string to be converted
   * @param origin If the name is not absolute, the origin to be appended.
   * @throws TextParseException The name is invalid.
   */
  public Name(String s, Name origin) throws TextParseException {
    switch (s) {
      case "":
        throw new TextParseException("empty name");
      case "@":
        if (origin == null) {
          copy(empty, this);
        } else {
          copy(origin, this);
        }
        return;
      case ".": // full stop
        copy(root, this);
        return;
    }
    int labelstart = -1;
    int pos = 0;
    char[] label = new char[MAXLABEL];
    boolean escaped = false;
    int digits = 0;
    int intval = 0;
    boolean absolute = false;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c > 0xff) {
        throw new TextParseException(s, "Illegal character in name");
      }
      if (escaped) {
        if (c >= '0' && c <= '9' && digits < 3) {
          digits++;
          intval *= 10;
          intval += c - '0';
          if (intval > 255) {
            throw new TextParseException(s, "bad escape");
          }
          if (digits < 3) {
            continue;
          }
          c = (char) intval;
        } else if (digits > 0 && digits < 3) {
          throw new TextParseException(s, "bad escape");
        }
        if (pos >= MAXLABEL) {
          throw new TextParseException(s, "label too long");
        }
        labelstart = pos;
        label[pos++] = c;
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
        digits = 0;
        intval = 0;
      } else if (c == '.') {
        if (labelstart == -1) {
          throw new TextParseException(s, "invalid empty label");
        }
        appendFromString(s, label, pos);
        labelstart = -1;
        pos = 0;
      } else {
        if (labelstart == -1) {
          labelstart = i;
        }
        if (pos >= MAXLABEL) {
          throw new TextParseException(s, "label too long");
        }
        label[pos++] = c;
      }
    }
    if (digits > 0 && digits < 3 || escaped) {
      throw new TextParseException(s, "bad escape");
    }
    if (labelstart == -1) {
      appendFromString(s, emptyLabel, 1);
      absolute = true;
    } else {
      appendFromString(s, label, pos);
    }
    if (origin != null && !absolute) {
      absolute = origin.isAbsolute();
      appendFromString(s, origin.name, origin.labels);
    }
    // A relative name that is MAXNAME octets long is a strange and wonderful thing.
    // Not technically in violation, but it can not be used for queries as it needs
    // to be made absolute by appending at the very least the empty label at the
    // end, which there is no room for. To make life easier for everyone, let's only
    // allow Names that are MAXNAME long if they are absolute.
    if (!absolute && length() == MAXNAME) {
      throw new TextParseException(s, "Name too long");
    }
  }

  /**
   * Create a new name from a string. This does not automatically make the name absolute; it will be
   * absolute if it has a trailing dot.
   *
   * @param s The string to be converted
   * @throws TextParseException The name is invalid.
   */
  public Name(String s) throws TextParseException {
    this(s, null);
  }

  /**
   * Create a new name from a string and an origin. This does not automatically make the name
   * absolute; it will be absolute if it has a trailing dot or an absolute origin is appended. This
   * is identical to the constructor, except that it will avoid creating new objects in some cases.
   *
   * @param s The string to be converted
   * @param origin If the name is not absolute, the origin to be appended.
   * @throws TextParseException The name is invalid.
   */
  public static Name fromString(String s, Name origin) throws TextParseException {
    if (s.equals("@")) {
      return origin != null ? origin : empty;
    } else if (s.equals(".")) {
      return root;
    }

    return new Name(s, origin);
  }

  /**
   * Create a new name from a string. This does not automatically make the name absolute; it will be
   * absolute if it has a trailing dot. This is identical to the constructor, except that it will
   * avoid creating new objects in some cases.
   *
   * @param s The string to be converted
   * @throws TextParseException The name is invalid.
   */
  public static Name fromString(String s) throws TextParseException {
    return fromString(s, null);
  }

  /**
   * Create a new name from a constant string. This should only be used when the name is known to be
   * good - that is, when it is constant.
   *
   * @param s The string to be converted
   * @throws IllegalArgumentException The name is invalid.
   */
  public static Name fromConstantString(String s) {
    try {
      return fromString(s, null);
    } catch (TextParseException e) {
      throw new IllegalArgumentException("Invalid name '" + s + "'");
    }
  }

  /**
   * Create a new name from DNS a wire format message
   *
   * @param in A stream containing the DNS message which is currently positioned at the start of the
   *     name to be read.
   */
  public Name(DNSInput in) throws WireParseException {
    int len;
    int pos;
    boolean done = false;
    byte[] label = new byte[MAXLABEL + 1];
    boolean savedState = false;

    while (!done) {
      len = in.readU8();
      switch (len & LABEL_MASK) {
        case LABEL_NORMAL:
          if (len == 0) {
            append(emptyLabel, 0, 1);
            done = true;
          } else {
            label[0] = (byte) len;
            in.readByteArray(label, 1, len);
            append(label, 0, 1);
          }
          break;
        case LABEL_COMPRESSION:
          pos = in.readU8();
          pos += (len & ~LABEL_MASK) << 8;
          log.trace("currently {}, pointer to {}", in.current(), pos);

          if (pos >= in.current() - 2) {
            throw new WireParseException("bad compression");
          }
          if (!savedState) {
            in.save();
            savedState = true;
          }
          in.jump(pos);
          log.trace("current name '{}', seeking to {}", this, pos);
          break;
        default:
          throw new WireParseException("bad label type");
      }
    }
    if (savedState) {
      in.restore();
    }
  }

  /**
   * Create a new name from DNS wire format
   *
   * @param b A byte array containing the wire format of the name.
   */
  public Name(byte[] b) throws IOException {
    this(new DNSInput(b));
  }

  /**
   * Create a new name by removing labels from the beginning of an existing Name
   *
   * @param src An existing Name
   * @param n The number of labels to remove from the beginning in the copy
   */
  public Name(Name src, int n) {
    if (n > src.labels) {
      throw new IllegalArgumentException("attempted to remove too many labels");
    }
    if (n == src.labels) {
      copy(empty, this);
      return;
    }

    labels = src.labels - n;
    name = Arrays.copyOfRange(src.name, src.offset(n), src.name.length);
    int strippedBytes = src.offset(n);
    for (int i = 1; i < MAXOFFSETS && i < labels; i++) {
      setOffset(i, src.offset(i + n) - strippedBytes);
    }
  }

  /**
   * Creates a new name by concatenating two existing names. If the {@code prefix} name is absolute
   * {@code prefix} is returned unmodified.
   *
   * @param prefix The prefix name. Must be relative.
   * @param suffix The suffix name.
   * @return The concatenated name.
   * @throws NameTooLongException The name is too long.
   */
  public static Name concatenate(Name prefix, Name suffix) throws NameTooLongException {
    if (prefix.isAbsolute()) {
      return prefix;
    }
    Name newname = new Name();
    newname.append(prefix.name, 0, prefix.labels);
    newname.append(suffix.name, 0, suffix.labels);
    return newname;
  }

  /**
   * If this name is a subdomain of origin, return a new name relative to origin with the same
   * value. Otherwise, return the existing name.
   *
   * @param origin The origin to remove.
   * @return The possibly relativized name.
   */
  public Name relativize(Name origin) {
    if (origin == null || !subdomain(origin)) {
      return this;
    }
    Name newname = new Name();
    int length = length() - origin.length();
    newname.labels = labels - origin.labels;
    newname.offsets = offsets;
    newname.name = new byte[length];
    System.arraycopy(name, 0, newname.name, 0, length);
    return newname;
  }

  /**
   * Generates a new Name with the first n labels replaced by a wildcard
   *
   * @return The wildcard name
   */
  public Name wild(int n) {
    if (n < 1) {
      throw new IllegalArgumentException("must replace 1 or more labels");
    }
    try {
      Name newname = new Name();
      copy(wild, newname);
      newname.append(name, offset(n), labels - n);
      return newname;
    } catch (NameTooLongException e) {
      throw new IllegalStateException("Name.wild: concatenate failed");
    }
  }

  /**
   * Returns a canonicalized version of the Name (all lowercase). This may be the same name, if the
   * input Name is already canonical.
   */
  public Name canonicalize() {
    boolean canonical = true;
    for (byte b : name) {
      if (lowercase[b & 0xFF] != b) {
        canonical = false;
        break;
      }
    }
    if (canonical) {
      return this;
    }

    Name newname = new Name();
    newname.offsets = offsets;
    newname.labels = labels;
    newname.name = new byte[length()];
    for (int i = 0; i < newname.name.length; i++) {
      newname.name[i] = lowercase[name[i] & 0xFF];
    }

    return newname;
  }

  /**
   * Generates a new Name to be used when following a DNAME.
   *
   * @param dname The DNAME record to follow.
   * @return The constructed name or {@code null} if this Name is not a subdomain of the {@code
   *     dname} name.
   * @throws NameTooLongException The resulting name is too long.
   */
  public Name fromDNAME(DNAMERecord dname) throws NameTooLongException {
    Name dnameowner = dname.getName();
    Name dnametarget = dname.getTarget();
    if (!subdomain(dnameowner)) {
      return null;
    }

    int plabels = labels - dnameowner.labels;
    int plength = length() - dnameowner.length();

    int dlabels = dnametarget.labels;
    int dlength = dnametarget.length();

    if (plength + dlength > MAXNAME) {
      throw new NameTooLongException();
    }

    Name newname = new Name();
    newname.labels = plabels + dlabels;
    newname.name = Arrays.copyOf(name, plength + dlength);
    System.arraycopy(dnametarget.name, 0, newname.name, plength, dlength);

    for (int i = 0, pos = 0; i < MAXOFFSETS && i < plabels + dlabels; i++) {
      newname.setOffset(i, pos);
      pos += newname.name[pos] + 1;
    }
    return newname;
  }

  /** Is this name a wildcard? */
  public boolean isWild() {
    if (labels == 0) {
      return false;
    }
    return name[0] == (byte) 1 && name[1] == (byte) '*';
  }

  /** Is this name absolute? */
  public boolean isAbsolute() {
    if (labels == 0) {
      return false;
    }
    return name[offset(labels - 1)] == 0;
  }

  /** The length of the name (in bytes). */
  public short length() {
    if (labels == 0) {
      return 0;
    }
    return (short) (name.length);
  }

  /** The number of labels in the name. */
  public int labels() {
    return labels;
  }

  /** Is the current Name a subdomain of the specified name? */
  public boolean subdomain(Name domain) {
    int dlabels = domain.labels;
    if (dlabels > labels) {
      return false;
    }
    if (dlabels == labels) {
      return equals(domain);
    }
    return domain.equals(name, offset(labels - dlabels));
  }

  private String byteString(byte[] array, int pos) {
    StringBuilder sb = new StringBuilder();
    int len = array[pos++];
    for (int i = pos; i < pos + len; i++) {
      int b = array[i] & 0xFF;
      if (b <= 0x20 || b >= 0x7f) {
        sb.append('\\');
        if (b < 10) {
          sb.append("00");
        } else if (b < 100) {
          sb.append('0');
        }
        sb.append(b);
      } else if (b == '"' || b == '(' || b == ')' || b == '.' || b == ';' || b == '\\' || b == '@'
          || b == '$') {
        sb.append('\\');
        sb.append((char) b);
      } else {
        sb.append((char) b);
      }
    }
    return sb.toString();
  }

  /**
   * Convert a Name to a String
   *
   * @param omitFinalDot If true, and the name is absolute, omit the final dot.
   * @return The representation of this name as a (printable) String.
   */
  public String toString(boolean omitFinalDot) {
    if (labels == 0) {
      return "@";
    } else if (labels == 1 && name[0] == 0) {
      return ".";
    }
    StringBuilder sb = new StringBuilder();
    for (int label = 0, pos = 0; label < labels; label++) {
      int len = name[pos];
      if (len == 0) {
        if (!omitFinalDot) {
          sb.append('.');
        }
        break;
      }
      if (label > 0) {
        sb.append('.');
      }
      sb.append(byteString(name, pos));
      pos += 1 + len;
    }
    return sb.toString();
  }

  /**
   * Convert a Name to a String
   *
   * @return The representation of this name as a (printable) String.
   */
  @Override
  public String toString() {
    return toString(false);
  }

  /**
   * Retrieve the nth label of a Name. This makes a copy of the label; changing this does not change
   * the Name. The returned byte array includes the label length as the first byte.
   *
   * @param n The label to be retrieved. The first label is 0.
   */
  public byte[] getLabel(int n) {
    int pos = offset(n);
    byte len = (byte) (name[pos] + 1);
    return Arrays.copyOfRange(name, pos, pos + len);
  }

  /**
   * Convert the nth label in a Name to a String
   *
   * @param n The label to be converted to a (printable) String. The first label is 0.
   */
  public String getLabelString(int n) {
    int pos = offset(n);
    return byteString(name, pos);
  }

  /**
   * Emit a Name in DNS wire format
   *
   * @param out The output stream containing the DNS message.
   * @param c The compression context, or null of no compression is desired.
   * @throws IllegalArgumentException The name is not absolute.
   */
  public void toWire(DNSOutput out, Compression c) {
    if (!isAbsolute()) {
      throw new IllegalArgumentException("toWire() called on non-absolute name");
    }

    for (int i = 0; i < labels - 1; i++) {
      Name tname;
      if (i == 0) {
        tname = this;
      } else {
        tname = new Name(this, i);
      }
      int pos = -1;
      if (c != null) {
        pos = c.get(tname);
      }
      if (pos >= 0) {
        pos |= LABEL_MASK << 8;
        out.writeU16(pos);
        return;
      } else {
        if (c != null) {
          c.add(out.current(), tname);
        }
        int off = offset(i);
        out.writeByteArray(name, off, name[off] + 1);
      }
    }
    out.writeU8(0);
  }

  /**
   * Emit a Name in DNS wire format
   *
   * @throws IllegalArgumentException The name is not absolute.
   */
  public byte[] toWire() {
    DNSOutput out = new DNSOutput();
    toWire(out, null);
    return out.toByteArray();
  }

  /**
   * Emit a Name in canonical DNS wire format (all lowercase)
   *
   * @param out The output stream to which the message is written.
   */
  public void toWireCanonical(DNSOutput out) {
    byte[] b = toWireCanonical();
    out.writeByteArray(b);
  }

  /**
   * Emit a Name in canonical DNS wire format (all lowercase)
   *
   * @return The canonical form of the name.
   */
  public byte[] toWireCanonical() {
    if (labels == 0) {
      return new byte[0];
    }
    byte[] b = new byte[name.length];
    for (int i = 0, spos = 0, dpos = 0; i < labels; i++) {
      int len = name[spos];
      b[dpos++] = name[spos++];
      for (int j = 0; j < len; j++) {
        b[dpos++] = lowercase[name[spos++] & 0xFF];
      }
    }
    return b;
  }

  /**
   * Emit a Name in DNS wire format
   *
   * @param out The output stream containing the DNS message.
   * @param c The compression context, or null of no compression is desired.
   * @param canonical If true, emit the name in canonicalized form (all lowercase).
   * @throws IllegalArgumentException The name is not absolute.
   */
  public void toWire(DNSOutput out, Compression c, boolean canonical) {
    if (canonical) {
      toWireCanonical(out);
    } else {
      toWire(out, c);
    }
  }

  private boolean equals(byte[] b, int bpos) {
    for (int i = 0, pos = 0; i < labels; i++) {
      if (name[pos] != b[bpos]) {
        return false;
      }
      int len = name[pos++];
      bpos++;
      for (int j = 0; j < len; j++) {
        if (lowercase[name[pos++] & 0xFF] != lowercase[b[bpos++] & 0xFF]) {
          return false;
        }
      }
    }
    return true;
  }

  /** Are these two Names equivalent? */
  @Override
  public boolean equals(Object arg) {
    if (arg == this) {
      return true;
    }
    if (!(arg instanceof Name)) {
      return false;
    }
    Name other = (Name) arg;
    if (other.labels != labels) {
      return false;
    }
    if (other.hashCode() != hashCode()) {
      return false;
    }
    return equals(other.name, 0);
  }

  /** Computes a hashcode based on the value */
  @Override
  public int hashCode() {
    if (hashcode != 0) {
      return hashcode;
    }
    int code = 0;
    for (int i = offset(0); i < name.length; i++) {
      code += (code << 3) + (lowercase[name[i] & 0xFF] & 0xFF);
    }
    hashcode = code;
    return hashcode;
  }

  /**
   * Compares this Name to another Object.
   *
   * @param arg The name to be compared.
   * @return The value 0 if the argument is a name equivalent to this name; a value less than 0 if
   *     the argument is less than this name in the canonical ordering, and a value greater than 0
   *     if the argument is greater than this name in the canonical ordering.
   * @throws ClassCastException if the argument is not a Name.
   */
  @Override
  public int compareTo(Name arg) {
    if (this == arg) {
      return 0;
    }

    int alabels = arg.labels;
    int compares = Math.min(labels, alabels);

    for (int i = 1; i <= compares; i++) {
      int start = offset(labels - i);
      int astart = arg.offset(alabels - i);
      int length = name[start];
      int alength = arg.name[astart];
      for (int j = 0; j < length && j < alength; j++) {
        int n =
            (lowercase[name[j + start + 1] & 0xFF] & 0xFF)
                - (lowercase[arg.name[j + astart + 1] & 0xFF] & 0xFF);
        if (n != 0) {
          return n;
        }
      }
      if (length != alength) {
        return length - alength;
      }
    }
    return labels - alabels;
  }
}

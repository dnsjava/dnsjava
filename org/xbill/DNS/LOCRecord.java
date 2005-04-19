// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.text.*;

/**
 * Location - describes the physical location of hosts, networks, subnets.
 *
 * @author Brian Wellington
 */

public class LOCRecord extends Record {

private static NumberFormat w2, w3;

private long size, hPrecision, vPrecision;
private long latitude, longitude, altitude;

static {
	w2 = new DecimalFormat();
	w2.setMaximumFractionDigits(2);
	w2.setGroupingUsed(false);

	w3 = new DecimalFormat();
	w3.setMaximumFractionDigits(3);
	w3.setGroupingUsed(false);
}

LOCRecord() {}

Record
getObject() {
	return new LOCRecord();
}

/**
 * Creates an LOC Record from the given data
 * @param latitude The latitude of the center of the sphere
 * @param longitude The longitude of the center of the sphere
 * @param altitude The altitude of the center of the sphere, in m
 * @param size The diameter of a sphere enclosing the described entity, in m.
 * @param hPrecision The horizontal precision of the data, in m.
 * @param vPrecision The vertical precision of the data, in m.
*/
public
LOCRecord(Name name, int dclass, long ttl, double latitude, double longitude,
	  double altitude, double size, double hPrecision, double vPrecision)
{
	super(name, Type.LOC, dclass, ttl);
	this.latitude = (long)(latitude * 3600 * 1000 + (1L << 31));
	this.longitude = (long)(longitude * 3600 * 1000 + (1L << 31));
	this.altitude = (long)((altitude + 100000) * 100);
	this.size = (long)(size * 100);
	this.hPrecision = (long)(hPrecision * 100);
	this.vPrecision = (long)(vPrecision * 100);
}

void
rrFromWire(DNSInput in) throws IOException {
	int version;

	version = in.readU8();
	if (version != 0)
		throw new WireParseException("Invalid LOC version");

	size = parseLOCformat(in.readU8());
	hPrecision = parseLOCformat(in.readU8());
	vPrecision = parseLOCformat(in.readU8());
	latitude = in.readU32();
	longitude = in.readU32();
	altitude = in.readU32();
}

private long
parsePosition(Tokenizer st, String type) throws IOException {
	boolean isLatitude = type.equals("latitude");
	int deg = 0, min = 0;
	double sec = 0;
	long value;
	String s;

	deg = st.getUInt16();
	if (deg > 180 || (deg > 90 && isLatitude))
		throw st.exception("Invalid LOC " + type + " degrees");

	s = st.getString();
	try {
		min = Integer.parseInt(s);
		if (min < 0 || min > 59)
			throw st.exception("Invalid LOC " + type + " minutes");
		s = st.getString();
		sec = Double.parseDouble(s);
		if (sec < 0 || sec >= 60)
			throw st.exception("Invalid LOC " + type + " seconds");
		s = st.getString();
	} catch (NumberFormatException e) {
	}

	if (s.length() != 1)
		throw st.exception("Invalid LOC " + type);

	value = (long) (1000 * (sec + 60L * (min + 60L * deg)));

	char c = Character.toUpperCase(s.charAt(0));
	if ((isLatitude && c == 'S') || (!isLatitude && c == 'W'))
		value = -value;
	else if ((isLatitude && c != 'N') || (!isLatitude && c != 'E'))
		throw st.exception("Invalid LOC " + type);

	value += (1L << 31);

	return value;
}

private long
parseDouble(Tokenizer st, String type, boolean required, long min, long max,
	    long defaultValue)
throws IOException
{
	Tokenizer.Token token = st.get();
	if (token.isEOL()) {
		if (required)
			throw st.exception("Invalid LOC " + type);
		st.unget();
		return defaultValue;
	}
	String s = token.value;
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		long value = (long)(100 * new Double(s).doubleValue());
		if (value < min || value > max)
			throw st.exception("Invalid LOC " + type);
		return value;
	}
	catch (NumberFormatException e) {
		throw st.exception("Invalid LOC " + type);
	}
}

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	String s = null;
	int deg, min;
	double sec;

	latitude = parsePosition(st, "latitude");
	longitude = parsePosition(st, "longitude");
	altitude = parseDouble(st, "altitude", true,
			       -10000000, 4284967295L, 0) + 10000000;
	size = parseDouble(st, "size", false, 0, 9000000000L, 100);
	hPrecision = parseDouble(st, "horizontal precision", false,
				 0, 9000000000L, 1000000);
	vPrecision = parseDouble(st, "vertical precision", false,
				 0, 9000000000L, 1000);
}

private String
positionToString(long value, char pos, char neg) {
	StringBuffer sb = new StringBuffer();
	char direction;

	long temp = value - (1L << 31);
	if (temp < 0) {
		temp = -temp;
		direction = neg;
	} else
		direction = pos;

	sb.append(temp / (3600 * 1000)); /* degrees */
	temp = temp % (3600 * 1000);
	sb.append(" ");

	sb.append(temp / (60 * 1000)); /* minutes */
	temp = temp % (60 * 1000);
	sb.append(" ");

	sb.append(w3.format(((double)temp) / 1000)); /* seconds */
	sb.append(" ");

	sb.append(direction);

	return sb.toString();
}


/** Convert to a String */
String
rrToString() {
	StringBuffer sb = new StringBuffer();
	long temp;
	char direction;

	/* Latitude */
	sb.append(positionToString(latitude, 'N', 'S'));
	sb.append(" ");

	/* Latitude */
	sb.append(positionToString(longitude, 'E', 'W'));
	sb.append(" ");

	/* Altitude */
	sb.append(w2.format((double)(altitude - 10000000)/100));
	sb.append("m ");

	/* Size */
	sb.append(w2.format((double)size/100));
	sb.append("m ");

	/* Horizontal precision */
	sb.append(w2.format((double)hPrecision/100));
	sb.append("m ");

	/* Vertical precision */
	sb.append(w2.format((double)vPrecision/100));
	sb.append("m");

	return sb.toString();
}

/** Returns the latitude */
public double
getLatitude() {  
	return ((double)(latitude - (1L << 31))) / (3600 * 1000);
}       

/** Returns the longitude */
public double
getLongitude() {  
	return ((double)(longitude - (1L << 31))) / (3600 * 1000);
}       

/** Returns the altitude */
public double
getAltitude() {  
	return ((double)(altitude - 10000000)) / 100;
}       

/** Returns the diameter of the enclosing sphere */
public double
getSize() {  
	return ((double)size) / 100;
}       

/** Returns the horizontal precision */
public double
getHPrecision() {  
	return ((double)hPrecision) / 100;
}       

/** Returns the horizontal precision */
public double
getVPrecision() {  
	return ((double)vPrecision) / 100;
}       

void
rrToWire(DNSOutput out, Compression c, boolean canonical) {
	out.writeU8(0); /* version */
	out.writeU8(toLOCformat(size));
	out.writeU8(toLOCformat(hPrecision));
	out.writeU8(toLOCformat(vPrecision));
	out.writeU32(latitude);
	out.writeU32(longitude);
	out.writeU32(altitude);
}

private static long
parseLOCformat(int b) throws WireParseException {
	long out = b >> 4;
	int exp = b & 0xF;
	if (out > 9 || exp > 9)
		throw new WireParseException("Invalid LOC Encoding");
	while (exp-- > 0)
		out *= 10;
	return (out);
}

private byte
toLOCformat(long l) {
	byte exp = 0;
	while (l > 9) {
		exp++;
		l = (l + 5) / 10;
	}
	return (byte)((l << 4) + exp);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;
import java.util.*;
import java.text.*;
import org.xbill.DNS.utils.*;

/**
 * Location - describes the physical location of hosts, networks, subnets.
 *
 * @author Brian Wellington
 */

public class LOCRecord extends Record {

private static LOCRecord member = new LOCRecord();

private long size, hPrecision, vPrecision;
private int latitude, longitude, altitude;

private
LOCRecord() {}

private
LOCRecord(Name name, short dclass, int ttl) {
	super(name, Type.LOC, dclass, ttl);
}

static LOCRecord
getMember() {
	return member;
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
LOCRecord(Name name, short dclass, int ttl, double latitude, double longitude,
	  double altitude, double size, double hPrecision, double vPrecision)
{
	this(name, dclass, ttl);
	this.latitude = (int)(latitude * 3600 * 1000 + (1 << 31));
	this.longitude = (int)(longitude * 3600 * 1000 + (1 << 31));
	this.altitude = (int)((altitude + 100000) * 100);
	this.size = (long)(size * 100);
	this.hPrecision = (long)(hPrecision * 100);
	this.vPrecision = (long)(vPrecision * 100);
}

Record
rrFromWire(Name name, short type, short dclass, int ttl, int length,
	   DataByteInputStream in)
throws IOException
{
	LOCRecord rec = new LOCRecord(name, dclass, ttl);
	if (in == null)
		return rec;
	int version, temp;

	version = in.readByte();
	if (version != 0)
		throw new WireParseException("Invalid LOC version");

	rec.size = parseLOCformat(in.readUnsignedByte());
	rec.hPrecision = parseLOCformat(in.readUnsignedByte());
	rec.vPrecision = parseLOCformat(in.readUnsignedByte());
	rec.latitude = in.readInt();
	rec.longitude = in.readInt();
	rec.altitude = in.readInt();
	return rec;
}

Record
rdataFromString(Name name, short dclass, int ttl, MyStringTokenizer st,
		Name origin)
throws TextParseException
{
	LOCRecord rec = new LOCRecord(name, dclass, ttl);

	String s = null;
	int deg, min;
	double sec;

	/* Latitude */
	deg = min = 0;
	sec = 0.0;
	try {
		s = nextString(st);
		deg = Integer.parseInt(s);
		s = nextString(st);
		min = Integer.parseInt(s);
		s = nextString(st);
		sec = new Double(s).doubleValue();
		s = nextString(st);
	}
	catch (NumberFormatException e) {
	}
	if (!s.equalsIgnoreCase("S") && !s.equalsIgnoreCase("N"))
		throw new TextParseException("Invalid LOC latitude");
	rec.latitude = (int) (1000 * (sec + 60 * (min + 60 * deg)));
	if (s.equalsIgnoreCase("S"))
		rec.latitude = -rec.latitude;
	rec.latitude += (1 << 31);
	
	/* Longitude */
	deg = min = 0;
	sec = 0.0;
	try {
		s = nextString(st);
		deg = Integer.parseInt(s);
		s = nextString(st);
		min = Integer.parseInt(s);
		s = nextString(st);
		sec = new Double(s).doubleValue();
		s = nextString(st);
	}
	catch (NumberFormatException e) {
	}
	if (!s.equalsIgnoreCase("W") && !s.equalsIgnoreCase("E"))
		throw new TextParseException("Invalid LOC longitude");
	rec.longitude = (int) (1000 * (sec + 60 * (min + 60 * deg)));
	if (s.equalsIgnoreCase("W"))
		rec.longitude = -rec.longitude;
	rec.longitude += (1 << 31);

	/* Altitude */
	if (!st.hasMoreTokens())
		return rec;
	s = nextString(st);
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		rec.altitude = (int)((new Double(s).doubleValue() + 100000) *
				     100);
	}
	catch (NumberFormatException e) {
		throw new TextParseException("Invalid LOC altitude");
	}
	
	/* Size */
	if (!st.hasMoreTokens())
		return rec;
	s = nextString(st);
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		rec.size = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw new TextParseException("Invalid LOC size");
	}
	
	/* Horizontal precision */
	if (!st.hasMoreTokens())
		return rec;
	s = nextString(st);
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		rec.hPrecision = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw new TextParseException("Invalid LOC horizontal " +
					     "precision");
	}
	
	/* Vertical precision */
	if (!st.hasMoreTokens())
		return rec;
	s = nextString(st);
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		rec.vPrecision = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw new TextParseException("Invalid LOC vertical precision");
	}
	return rec;
}

/** Convert to a String */
public String
rdataToString() {
	StringBuffer sb = new StringBuffer();
	if (latitude != 0 || longitude != 0 || altitude != 0) {
		long temp;
		char direction;
		NumberFormat nf = new DecimalFormat();
		nf.setMaximumFractionDigits(3);
		nf.setGroupingUsed(false);

		/* Latitude */
		temp = (latitude & 0xFFFFFFFF) - (1 << 31);
		if (temp < 0) {
			temp = -temp;
			direction = 'S';
		}
		else
			direction = 'N';

		sb.append(temp / (3600 * 1000)); /* degrees */
		temp = temp % (3600 * 1000);
		sb.append(" ");

		sb.append(temp / (60 * 1000)); /* minutes */
		temp = temp % (60 * 1000);
		sb.append(" ");

		sb.append(nf.format((double)temp / 1000)); /* seconds */
		sb.append(" ");

		sb.append(direction);
		sb.append(" ");

		/* Latitude */
		temp = (longitude & 0xFFFFFFFF) - (1 << 31);
		if (temp < 0) {
			temp = -temp;
			direction = 'W';
		}
		else
			direction = 'E';

		sb.append(temp / (3600 * 1000)); /* degrees */
		temp = temp % (3600 * 1000);
		sb.append(" ");

		sb.append(temp / (60 * 1000)); /* minutes */
		temp = temp % (60 * 1000);
		sb.append(" ");

		sb.append(nf.format((double)temp / 1000)); /* seconds */
		sb.append(" ");

		sb.append(direction);
		sb.append(" ");

		nf.setMaximumFractionDigits(2);

		/* Altitude */
		sb.append(nf.format((double)(altitude - 10000000)/100));
		sb.append("m ");

		/* Size */
		sb.append(nf.format((double)size/100));
		sb.append("m ");

		/* Horizontal precision */
		sb.append(nf.format((double)hPrecision/100));
		sb.append("m ");

		/* Vertical precision */
		sb.append(nf.format((double)vPrecision/100));
		sb.append("m");
	}
	return sb.toString();
}

/** Returns the latitude */
public double
getLatitude() {  
	return (double)(latitude - (1<<31)) / (3600 * 1000);
}       

/** Returns the longitude */
public double
getLongitude() {  
	return (double)(longitude - (1<<31)) / (3600 * 1000);
}       

/** Returns the altitude */
public double
getAltitude() {  
	return (double)(altitude - 10000000)/100;
}       

/** Returns the diameter of the enclosing sphere */
public double
getSize() {  
	return (double)size / 100;
}       

/** Returns the horizontal precision */
public double
getHPrecision() {  
	return (double)hPrecision / 100;
}       

/** Returns the horizontal precision */
public double
getVPrecision() {  
	return (double)vPrecision / 100;
}       

void
rrToWire(DataByteOutputStream out, Compression c, boolean canonical) {
	if (latitude == 0 && longitude == 0 && altitude == 0)
		return;

	out.writeByte(0); /* version */
	out.writeByte(toLOCformat(size));
	out.writeByte(toLOCformat(hPrecision));
	out.writeByte(toLOCformat(vPrecision));
	out.writeInt(latitude);
	out.writeInt(longitude);
	out.writeInt(altitude);
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

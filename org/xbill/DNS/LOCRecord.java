// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;
import java.text.*;
import org.xbill.DNS.utils.*;

/**
 * Location - describes the physical location of hosts, networks, subnets.
 *
 * @author Brian Wellington
 */

public class LOCRecord extends Record {

private long size, hPrecision, vPrecision;
private long latitude, longitude, altitude;

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
	this.latitude = (int)(latitude * 3600 * 1000 + (1 << 31));
	this.longitude = (int)(longitude * 3600 * 1000 + (1 << 31));
	this.altitude = (int)((altitude + 100000) * 100);
	this.size = (long)(size * 100);
	this.hPrecision = (long)(hPrecision * 100);
	this.vPrecision = (long)(vPrecision * 100);
}

void
rrFromWire(DNSInput in) throws IOException {
	if (in == null)
		return;

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

void
rdataFromString(Tokenizer st, Name origin) throws IOException {
	String s = null;
	int deg, min;
	double sec;

	/* Latitude */
	deg = min = 0;
	sec = 0.0;
	try {
		deg = st.getUInt16();
		min = st.getUInt16();
		sec = st.getDouble();
	}
	catch (NumberFormatException e) {
		st.unget();
	}
	s = st.getString();
	if (!s.equalsIgnoreCase("S") && !s.equalsIgnoreCase("N"))
		throw st.exception("Invalid LOC latitude");
	latitude = (int) (1000 * (sec + 60 * (min + 60 * deg)));
	if (s.equalsIgnoreCase("S"))
		latitude = -latitude;
	latitude += (1 << 31);
	
	/* Longitude */
	deg = min = 0;
	sec = 0.0;
	try {
		deg = st.getUInt16();
		min = st.getUInt16();
		sec = st.getDouble();
	}
	catch (NumberFormatException e) {
		st.unget();
	}
	s = st.getString();
	if (!s.equalsIgnoreCase("W") && !s.equalsIgnoreCase("E"))
		throw st.exception("Invalid LOC longitude");
	longitude = (int) (1000 * (sec + 60 * (min + 60 * deg)));
	if (s.equalsIgnoreCase("W"))
		longitude = -longitude;
	longitude += (1 << 31);

	/* Altitude */
	Tokenizer.Token token = st.get();
	if (token.isEOL()) {
		st.unget();
		return;
	}
	s = token.value;
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		altitude = (int)((new Double(s).doubleValue() + 100000) * 100);
	}
	catch (NumberFormatException e) {
		throw st.exception("Invalid LOC altitude");
	}
	
	/* Size */
	token = st.get();
	if (token.isEOL()) {
		st.unget();
		return;
	}
	s = token.value;
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		size = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw st.exception("Invalid LOC size");
	}
	
	/* Horizontal precision */
	token = st.get();
	if (token.isEOL()) {
		st.unget();
		return;
	}
	s = token.value;
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		hPrecision = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw st.exception("Invalid LOC horizontal precision");
	}
	
	/* Vertical precision */
	token = st.get();
	if (token.isEOL()) {
		st.unget();
		return;
	}
	s = token.value;
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		vPrecision = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw st.exception("Invalid LOC vertical precision");
	}
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
	out.writeUnsignedInt(latitude);
	out.writeUnsignedInt(longitude);
	out.writeUnsignedInt(altitude);
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

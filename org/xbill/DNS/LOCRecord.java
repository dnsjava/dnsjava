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

private long size, hPrecision, vPrecision;
private int latitude, longitude, altitude;

private
LOCRecord() {}

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
LOCRecord(Name _name, short _dclass, int _ttl, double _latitude,
	  double _longitude, double _altitude, double _size,
	  double _hPrecision, double _vPrecision)
throws IOException
{
	super(_name, Type.LOC, _dclass, _ttl);
	latitude = (int)(_latitude * 3600 * 1000 + (1 << 31));
	longitude = (int)(_longitude * 3600 * 1000 + (1 << 31));
	altitude = (int)((_altitude + 100000) * 100);
	size = (long)(_size * 100);
	hPrecision = (long)(_hPrecision * 100);
	vPrecision = (long)(_vPrecision * 100);
}

LOCRecord(Name _name, short _dclass, int _ttl, int length,
	  DataByteInputStream in, Compression c) throws IOException
{
	super(_name, Type.LOC, _dclass, _ttl);
	if (in == null)
		return;
	int version, temp;

	version = in.readByte();
	if (version != 0)
		throw new WireParseException("Invalid LOC version");

	size = parseLOCformat(in.readUnsignedByte());
	hPrecision = parseLOCformat(in.readUnsignedByte());
	vPrecision = parseLOCformat(in.readUnsignedByte());
	latitude = in.readInt();
	longitude = in.readInt();
	altitude = in.readInt();
}

LOCRecord(Name _name, short _dclass, int _ttl, MyStringTokenizer st,
	     Name origin)
throws IOException
{
	super(_name, Type.LOC, _dclass, _ttl);

	String s = null;
	int deg, min;
	double sec;

	/* Latitude */
	deg = min = 0;
	sec = 0.0;
	try {
		s = st.nextToken();
		deg = Integer.parseInt(s);
		s = st.nextToken();
		min = Integer.parseInt(s);
		s = st.nextToken();
		sec = new Double(s).doubleValue();
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
	}
	if (!s.equalsIgnoreCase("S") && !s.equalsIgnoreCase("N"))
		throw new WireParseException("Invalid LOC latitude");
	latitude = (int) (1000 * (sec + 60 * (min + 60 * deg)));
	if (s.equalsIgnoreCase("S"))
		latitude = -latitude;
	latitude += (1 << 31);
	
	/* Longitude */
	deg = min = 0;
	sec = 0.0;
	try {
		s = st.nextToken();
		deg = Integer.parseInt(s);
		s = st.nextToken();
		min = Integer.parseInt(s);
		s = st.nextToken();
		sec = new Double(s).doubleValue();
		s = st.nextToken();
	}
	catch (NumberFormatException e) {
	}
	if (!s.equalsIgnoreCase("W") && !s.equalsIgnoreCase("E"))
		throw new WireParseException("Invalid LOC longitude");
	longitude = (int) (1000 * (sec + 60 * (min + 60 * deg)));
	if (s.equalsIgnoreCase("W"))
		longitude = -longitude;
	longitude += (1 << 31);

	/* Altitude */
	if (!st.hasMoreTokens())
		return;
	s = st.nextToken();
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		altitude = (int)((new Double(s).doubleValue() + 100000) * 100);
	}
	catch (NumberFormatException e) {
		throw new WireParseException("Invalid LOC altitude");
	}
	
	/* Size */
	if (!st.hasMoreTokens())
		return;
	s = st.nextToken();
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		size = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw new WireParseException("Invalid LOC size");
	}
	
	/* Horizontal precision */
	if (!st.hasMoreTokens())
		return;
	s = st.nextToken();
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		hPrecision = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw new WireParseException("Invalid LOC horizontal precision");
	}
	
	/* Vertical precision */
	if (!st.hasMoreTokens())
		return;
	s = st.nextToken();
	if (s.length() > 1 && s.charAt(s.length() - 1) == 'm')
		s = s.substring(0, s.length() - 1);
	try {
		vPrecision = (int) (100 * new Double(s).doubleValue());
	}
	catch (NumberFormatException e) {
		throw new WireParseException("Invalid LOC vertical precision");
	}
}

/** Convert to a String */
public String
toString() {
	StringBuffer sb = toStringNoData();
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
rrToWire(DataByteOutputStream out, Compression c) throws IOException {
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

private long
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

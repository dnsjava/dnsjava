// Copyright (c) 2003 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

import java.io.*;

/**
 * An exception thrown when an invalid type code is specified.
 *
 * @author Brian Wellington
 */

public class InvalidTypeException extends IllegalArgumentException {

public
InvalidTypeException(int type) {
	super("Invalid DNS type: " + type);
}

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package org.xbill.DNS;

import java.io.*;

/**
 * An exception thrown when a DNS message is invalid.
 *
 * @author Brian Wellington
 */

public class WireParseException extends IOException {

public
WireParseException() {
	super();
}

public
WireParseException(String s) {
	super(s);
}

}

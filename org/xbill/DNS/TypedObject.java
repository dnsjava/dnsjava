// Copyright (c) 2002 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS;

/**
 * Interface describing an object with a DNS type.
 *
 * @author Brian Wellington
 */

interface TypedObject {

/**
 * Gets the type.
 */
int getType();

}

// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.util.EventListener;

public interface ResolverListener extends EventListener {

public void receiveMessage(int id, Message m);

}

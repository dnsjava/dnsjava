// Copyright (c) 1999 Brian Wellington (bwelling@xbill.org)
// Portions Copyright (c) 1999 Network Associates, Inc.

package DNS;

import java.io.*;

public interface Resolver {

public void setPort(int port);
public void setTCP(boolean flag);
public void setIgnoreTruncation(boolean flag);
public void setEDNS(int level);
public void setTSIGKey(String name, String key);
public void setTSIGKey(String key);
public void setTimeout(int secs);
public Message send(Message query) throws IOException;
public int sendAsync(final Message query, final ResolverListener listener);
public Message sendAXFR(Message query) throws IOException;

}

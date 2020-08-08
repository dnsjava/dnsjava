// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
package org.xbill.DNS.tools;

import java.io.IOException;
import java.net.InetAddress;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;
import org.xbill.DNS.ZoneTransferException;
import org.xbill.DNS.ZoneTransferIn;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */
public class dig {
  static Name name = null;
  static int type = Type.A, dclass = DClass.IN;

  static void usage() {
    System.out.println("; dnsjava dig");
    System.out.println("Usage: dig [@server] name [<type>] [<class>] [options]");
    System.exit(0);
  }

  static void doQuery(Message response, long ms) {
    System.out.println("; dnsjava dig");
    System.out.println(response);
    System.out.println(";; Query time: " + ms + " ms");
  }

  public static void main(String[] argv) throws IOException {
    String server = null;
    int arg;
    Message query, response;
    Record rec;
    SimpleResolver res = null;
    boolean printQuery = false;
    long startTime, endTime;

    if (argv.length < 1) {
      usage();
    }

    try {
      arg = 0;
      if (argv[arg].startsWith("@")) {
        server = argv[arg++].substring(1);
      }

      if (server != null) {
        res = new SimpleResolver(server);
      } else {
        res = new SimpleResolver();
      }

      String nameString = argv[arg++];
      if (nameString.equals("-x")) {
        name = ReverseMap.fromAddress(argv[arg++]);
        type = Type.PTR;
        dclass = DClass.IN;
      } else {
        name = Name.fromString(nameString, Name.root);
        type = Type.value(argv[arg]);
        if (type < 0) {
          type = Type.A;
        } else {
          arg++;
        }

        dclass = DClass.value(argv[arg]);
        if (dclass < 0) {
          dclass = DClass.IN;
        } else {
          arg++;
        }
      }

      while (argv[arg].startsWith("-") && argv[arg].length() > 1) {
        switch (argv[arg].charAt(1)) {
          case 'p':
            String portStr;
            int port;
            if (argv[arg].length() > 2) {
              portStr = argv[arg].substring(2);
            } else {
              portStr = argv[++arg];
            }
            port = Integer.parseInt(portStr);
            if (port < 0 || port > 65535) {
              System.out.println("Invalid port");
              return;
            }
            res.setPort(port);
            break;

          case 'b':
            String addrStr;
            if (argv[arg].length() > 2) {
              addrStr = argv[arg].substring(2);
            } else {
              addrStr = argv[++arg];
            }
            InetAddress addr;
            try {
              addr = InetAddress.getByName(addrStr);
            } catch (Exception e) {
              System.out.println("Invalid address");
              return;
            }
            res.setLocalAddress(addr);
            break;

          case 'k':
            String key;
            if (argv[arg].length() > 2) {
              key = argv[arg].substring(2);
            } else {
              key = argv[++arg];
            }

            String[] parts = key.split("[:/]", 3);
            switch (parts.length) {
              case 2:
                res.setTSIGKey(new TSIG(TSIG.HMAC_MD5, parts[0], parts[1]));
                break;
              case 3:
                res.setTSIGKey(new TSIG(parts[0], parts[1], parts[2]));
                break;
              default:
                throw new IllegalArgumentException("Invalid TSIG key specification");
            }
            break;

          case 't':
            res.setTCP(true);
            break;

          case 'i':
            res.setIgnoreTruncation(true);
            break;

          case 'e':
            String ednsStr;
            int edns;
            if (argv[arg].length() > 2) {
              ednsStr = argv[arg].substring(2);
            } else {
              ednsStr = argv[++arg];
            }
            edns = Integer.parseInt(ednsStr);
            if (edns < 0 || edns > 1) {
              System.out.println("Unsupported EDNS level: " + edns);
              return;
            }
            res.setEDNS(edns);
            break;

          case 'd':
            res.setEDNS(0, 0, ExtendedFlags.DO);
            break;

          case 'q':
            printQuery = true;
            break;

          default:
            System.out.print("Invalid option: ");
            System.out.println(argv[arg]);
        }
        arg++;
      }

    } catch (ArrayIndexOutOfBoundsException e) {
      if (name == null) {
        usage();
      }
    }
    if (res == null) {
      res = new SimpleResolver();
    }

    rec = Record.newRecord(name, type, dclass);
    query = Message.newQuery(rec);
    if (printQuery) {
      System.out.println(query);
    }

    if (type == Type.AXFR) {
      System.out.println("; dnsjava dig <> " + name + " axfr");
      ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(name, res.getAddress(), res.getTSIGKey());
      xfrin.setTimeout(res.getTimeout());
      try {
        xfrin.run(
            new ZoneTransferIn.ZoneTransferHandler() {
              @Override
              public void startAXFR() {}

              @Override
              public void startIXFR() {}

              @Override
              public void startIXFRDeletes(Record soa) {}

              @Override
              public void startIXFRAdds(Record soa) {}

              @Override
              public void handleRecord(Record r) {
                System.out.println(r);
              }
            });
      } catch (ZoneTransferException e) {
        throw new WireParseException(e.getMessage());
      }
    } else {
      startTime = System.currentTimeMillis();
      response = res.send(query);
      endTime = System.currentTimeMillis();
      doQuery(response, endTime - startTime);
    }
  }
}

// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
package org.xbill.DNS.tools;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.PrintStream;
import java.net.SocketException;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TTL;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */
public class update {

  Message query, response;
  Resolver res;
  String server = null;
  Name zone = Name.root;
  long defaultTTL;
  int defaultClass = DClass.IN;
  PrintStream log = null;

  void print(Object o) {
    System.out.println(o);
    if (log != null) {
      log.println(o);
    }
  }

  public Message newMessage() {
    Message msg = new Message();
    msg.getHeader().setOpcode(Opcode.UPDATE);
    return msg;
  }

  public update(InputStream in) {
    List<BufferedReader> inputs = new LinkedList<>();
    List<InputStream> istreams = new LinkedList<>();

    query = newMessage();

    InputStreamReader isr = new InputStreamReader(in);
    BufferedReader br = new BufferedReader(isr);

    inputs.add(br);
    istreams.add(in);

    while (true) {
      try {
        String line;
        do {
          InputStream is;
          is = istreams.get(0);
          br = inputs.get(0);

          if (is == System.in) {
            System.out.print("> ");
          }

          line = br.readLine();
          if (line == null) {
            br.close();
            inputs.remove(0);
            istreams.remove(0);
            if (inputs.isEmpty()) {
              return;
            }
          }
        } while (line == null);

        if (log != null) {
          log.println("> " + line);
        }

        if (line.length() == 0 || line.charAt(0) == '#') {
          continue;
        }

        /* Allows cut and paste from other update sessions */
        if (line.charAt(0) == '>') {
          line = line.substring(1);
        }

        Tokenizer st = new Tokenizer(line);
        Tokenizer.Token token = st.get();

        if (token.isEOL()) {
          continue;
        }
        String operation = token.value;

        switch (operation) {
          case "server":
            server = st.getString();
            res = new SimpleResolver(server);
            token = st.get();
            if (token.isString()) {
              String portstr = token.value;
              res.setPort(Short.parseShort(portstr));
            }
            break;
          case "key":
            String keyname = st.getString();
            String keydata = st.getString();
            if (res == null) {
              res = new SimpleResolver(server);
            }
            res.setTSIGKey(new TSIG(TSIG.HMAC_MD5, keyname, keydata));
            break;
          case "edns":
            if (res == null) {
              res = new SimpleResolver(server);
            }
            res.setEDNS(st.getUInt16());
            break;
          case "port":
            if (res == null) {
              res = new SimpleResolver(server);
            }
            res.setPort(st.getUInt16());
            break;
          case "tcp":
            if (res == null) {
              res = new SimpleResolver(server);
            }
            res.setTCP(true);
            break;
          case "class":
            String classStr = st.getString();
            int newClass = DClass.value(classStr);
            if (newClass > 0) {
              defaultClass = newClass;
            } else {
              print("Invalid class " + classStr);
            }
            break;
          case "ttl":
            defaultTTL = st.getTTL();
            break;
          case "origin":
          case "zone":
            zone = st.getName(Name.root);
            break;
          case "require":
            doRequire(st);
            break;
          case "prohibit":
            doProhibit(st);
            break;
          case "add":
            doAdd(st);
            break;
          case "delete":
            doDelete(st);
            break;
          case "glue":
            doGlue(st);
            break;
          case "help":
          case "?":
            token = st.get();
            if (token.isString()) {
              help(token.value);
            } else {
              help(null);
            }
            break;
          case "echo":
            print(line.substring(4).trim());
            break;
          case "send":
            sendUpdate();
            query = newMessage();
            break;
          case "show":
            print(query);
            break;
          case "clear":
            query = newMessage();
            break;
          case "query":
            doQuery(st);
            break;
          case "quit":
          case "q":
            if (log != null) {
              log.close();
            }
            for (Object input : inputs) {
              BufferedReader tbr;
              tbr = (BufferedReader) input;
              tbr.close();
            }
            System.exit(0);
          case "file":
            doFile(st, inputs, istreams);
            break;
          case "log":
            doLog(st);
            break;
          case "assert":
            if (!doAssert(st)) {
              return;
            }
            break;
          case "sleep":
            long interval = st.getUInt32();
            try {
              Thread.sleep(interval);
            } catch (InterruptedException e) {
              throw new IOException(e);
            }
            break;
          case "date":
            Instant now = Instant.now();
            token = st.get();
            if (token.isString() && token.value.equals("-ms")) {
              print(Long.toString(now.toEpochMilli()));
            } else {
              print(now);
            }
            break;
          default:
            print("invalid keyword: " + operation);
            break;
        }
      } catch (TextParseException tpe) {
        System.out.println(tpe.getMessage());
      } catch (InterruptedIOException iioe) {
        System.out.println("Operation timed out");
      } catch (SocketException se) {
        System.out.println("Socket error");
      } catch (IOException ioe) {
        System.out.println(ioe);
      }
    }
  }

  void sendUpdate() throws IOException {
    if (query.getHeader().getCount(Section.UPDATE) == 0) {
      print("Empty update message.  Ignoring.");
      return;
    }
    if (query.getHeader().getCount(Section.ZONE) == 0) {
      Name updzone;
      updzone = zone;
      int dclass = defaultClass;
      if (updzone == null) {
        for (Record rec : query.getSection(Section.UPDATE)) {
          if (updzone == null) {
            updzone = new Name(rec.getName(), 1);
          }
          if (rec.getDClass() != DClass.NONE && rec.getDClass() != DClass.ANY) {
            dclass = rec.getDClass();
            break;
          }
        }
      }
      Record soa = Record.newRecord(updzone, Type.SOA, dclass);
      query.addRecord(soa, Section.ZONE);
    }

    if (res == null) {
      res = new SimpleResolver(server);
    }
    response = res.send(query);
    print(response);
  }

  /*
   * <name> [ttl] [class] <type> <data>
   * Ignore the class, if present.
   */
  Record parseRR(Tokenizer st, int classValue, long TTLValue) throws IOException {
    Name name = st.getName(zone);
    long ttl;
    int type;

    String s = st.getString();

    try {
      ttl = TTL.parseTTL(s);
      s = st.getString();
    } catch (NumberFormatException e) {
      ttl = TTLValue;
    }

    if (DClass.value(s) >= 0) {
      classValue = DClass.value(s);
      s = st.getString();
    }

    if ((type = Type.value(s)) < 0) {
      throw new IOException("Invalid type: " + s);
    }

    return Record.fromString(name, type, classValue, ttl, st, zone);
  }

  void doRequire(Tokenizer st) throws IOException {
    Tokenizer.Token token;
    Name name;
    Record record;
    int type;

    name = st.getName(zone);
    token = st.get();
    if (token.isString()) {
      if ((type = Type.value(token.value)) < 0) {
        throw new IOException("Invalid type: " + token.value);
      }
      token = st.get();
      boolean iseol = token.isEOL();
      st.unget();
      if (!iseol) {
        record = Record.fromString(name, type, defaultClass, 0, st, zone);
      } else {
        record = Record.newRecord(name, type, DClass.ANY, 0);
      }
    } else {
      record = Record.newRecord(name, Type.ANY, DClass.ANY, 0);
    }

    query.addRecord(record, Section.PREREQ);
    print(record);
  }

  void doProhibit(Tokenizer st) throws IOException {
    Tokenizer.Token token;
    Name name;
    Record record;
    int type;

    name = st.getName(zone);
    token = st.get();
    if (token.isString()) {
      if ((type = Type.value(token.value)) < 0) {
        throw new IOException("Invalid type: " + token.value);
      }
    } else {
      type = Type.ANY;
    }
    record = Record.newRecord(name, type, DClass.NONE, 0);
    query.addRecord(record, Section.PREREQ);
    print(record);
  }

  void doAdd(Tokenizer st) throws IOException {
    Record record = parseRR(st, defaultClass, defaultTTL);
    query.addRecord(record, Section.UPDATE);
    print(record);
  }

  void doDelete(Tokenizer st) throws IOException {
    Tokenizer.Token token;
    String s;
    Name name;
    Record record;
    int type;

    name = st.getName(zone);
    token = st.get();
    if (token.isString()) {
      s = token.value;
      if (DClass.value(s) >= 0) {
        s = st.getString();
      }
      if ((type = Type.value(s)) < 0) {
        throw new IOException("Invalid type: " + s);
      }
      token = st.get();
      boolean iseol = token.isEOL();
      st.unget();
      if (!iseol) {
        record = Record.fromString(name, type, DClass.NONE, 0, st, zone);
      } else {
        record = Record.newRecord(name, type, DClass.ANY, 0);
      }
    } else {
      record = Record.newRecord(name, Type.ANY, DClass.ANY, 0);
    }

    query.addRecord(record, Section.UPDATE);
    print(record);
  }

  void doGlue(Tokenizer st) throws IOException {
    Record record = parseRR(st, defaultClass, defaultTTL);
    query.addRecord(record, Section.ADDITIONAL);
    print(record);
  }

  void doQuery(Tokenizer st) throws IOException {
    Record rec;
    Tokenizer.Token token;

    Name name;
    int type = Type.A;
    int dclass = defaultClass;

    name = st.getName(zone);
    token = st.get();
    if (token.isString()) {
      type = Type.value(token.value);
      if (type < 0) {
        throw new IOException("Invalid type");
      }
      token = st.get();
      if (token.isString()) {
        dclass = DClass.value(token.value);
        if (dclass < 0) {
          throw new IOException("Invalid class");
        }
      }
    }

    rec = Record.newRecord(name, type, dclass);
    Message newQuery = Message.newQuery(rec);
    if (res == null) {
      res = new SimpleResolver(server);
    }
    response = res.send(newQuery);
    print(response);
  }

  void doFile(Tokenizer st, List<BufferedReader> inputs, List<InputStream> istreams)
      throws IOException {
    String s = st.getString();
    InputStream is;
    try {
      if (s.equals("-")) {
        is = System.in;
      } else {
        is = new FileInputStream(s);
      }
      istreams.add(0, is);
      inputs.add(0, new BufferedReader(new InputStreamReader(is)));
    } catch (FileNotFoundException e) {
      print(s + " not found");
    }
  }

  void doLog(Tokenizer st) throws IOException {
    String s = st.getString();
    try {
      FileOutputStream fos = new FileOutputStream(s);
      log = new PrintStream(fos);
    } catch (Exception e) {
      print("Error opening " + s);
    }
  }

  boolean doAssert(Tokenizer st) throws IOException {
    String field = st.getString();
    String expected = st.getString();
    String value = null;
    boolean flag = true;
    int section;

    if (response == null) {
      print("No response has been received");
      return true;
    }
    if (field.equalsIgnoreCase("rcode")) {
      int rcode = response.getHeader().getRcode();
      if (rcode != Rcode.value(expected)) {
        value = Rcode.string(rcode);
        flag = false;
      }
    } else if (field.equalsIgnoreCase("serial")) {
      List<Record> answers = response.getSection(Section.ANSWER);
      if (answers.isEmpty() || !(answers.get(0) instanceof SOARecord)) {
        print("Invalid response (no SOA)");
      } else {
        SOARecord soa = (SOARecord) answers.get(0);
        long serial = soa.getSerial();
        if (serial != Long.parseLong(expected)) {
          value = Long.toString(serial);
          flag = false;
        }
      }
    } else if (field.equalsIgnoreCase("tsig")) {
      if (response.isSigned()) {
        if (response.isVerified()) {
          value = "ok";
        } else {
          value = "failed";
        }
      } else {
        value = "unsigned";
      }
      if (!value.equalsIgnoreCase(expected)) {
        flag = false;
      }
    } else if ((section = Section.value(field)) >= 0) {
      int count = response.getHeader().getCount(section);
      if (count != Integer.parseInt(expected)) {
        value = Integer.toString(count);
        flag = false;
      }
    } else {
      print("Invalid assertion keyword: " + field);
    }

    if (!flag) {
      print("Expected " + field + " " + expected + ", received " + value);
      while (true) {
        Tokenizer.Token token = st.get();
        if (!token.isString()) {
          break;
        }
        print(token.value);
      }
      st.unget();
    }
    return flag;
  }

  static void help(String topic) {
    System.out.println();
    if (topic == null) {
      System.out.println(
          "The following are supported commands:\n"
              + "add      assert   class    clear    date     delete\n"
              + "echo     edns     file     glue     help     key\n"
              + "log      port     prohibit query    quit     require\n"
              + "send     server   show     sleep    tcp      ttl\n"
              + "zone     #\n");
      return;
    }
    topic = topic.toLowerCase();

    switch (topic) {
      case "add":
        System.out.println(
            "add <name> [ttl] [class] <type> <data>\n\nspecify a record to be added\n");
        break;
      case "assert":
        System.out.println(
            "assert <field> <value> [msg]\n\n"
                + "asserts that the value of the field in the last\n"
                + "response matches the value specified.  If not,\n"
                + "the message is printed (if present) and the\n"
                + "program exits.  The field may be any of <rcode>,\n"
                + "<serial>, <tsig>, <qu>, <an>, <au>, or <ad>.\n");
        break;
      case "class":
        System.out.println("class <class>\n\nclass of the zone to be updated (default: IN)\n");
        break;
      case "clear":
        System.out.println("clear\n\nclears the current update packet\n");
        break;
      case "date":
        System.out.println(
            "date [-ms]\n\n"
                + "prints the current date and time in human readable\n"
                + "format or as the number of milliseconds since the\n"
                + "epoch");
        break;
      case "delete":
        System.out.println(
            "delete <name> [ttl] [class] <type> <data> \n"
                + "delete <name> <type> \n"
                + "delete <name>\n\n"
                + "specify a record or set to be deleted, or that\n"
                + "all records at a name should be deleted\n");
        break;
      case "echo":
        System.out.println("echo <text>\n\nprints the text\n");
        break;
      case "edns":
        System.out.println("edns <level>\n\nEDNS level specified when sending messages\n");
        break;
      case "file":
        System.out.println(
            "file <file>\n\n"
                + "opens the specified file as the new input source\n"
                + "(- represents stdin)\n");
        break;
      case "glue":
        System.out.println(
            "glue <name> [ttl] [class] <type> <data>\n\nspecify an additional record\n");
        break;
      case "help":
        System.out.println(
            "help\n"
                + "help [topic]\n\n"
                + "prints a list of commands or help about a specific\n"
                + "command\n");
        break;
      case "key":
        System.out.println("key <name> <data>\n\nTSIG key used to sign messages\n");
        break;
      case "log":
        System.out.println("log <file>\n\nopens the specified file and uses it to log output\n");
        break;
      case "port":
        System.out.println("port <port>\n\nUDP/TCP port messages are sent to (default: 53)\n");
        break;
      case "prohibit":
        System.out.println(
            "prohibit <name> <type> \n"
                + "prohibit <name>\n\n"
                + "require that a set or name is not present\n");
        break;
      case "query":
        System.out.println("query <name> [type [class]] \n\nissues a query\n");
        break;
      case "q":
      case "quit":
        System.out.println("quit\n\nquits the program\n");
        break;
      case "require":
        System.out.println(
            "require <name> [ttl] [class] <type> <data> \n"
                + "require <name> <type> \n"
                + "require <name>\n\n"
                + "require that a record, set, or name is present\n");
        break;
      case "send":
        System.out.println("send\n\nsends and resets the current update packet\n");
        break;
      case "server":
        System.out.println("server <name> [port]\n\nserver that receives send updates/queries\n");
        break;
      case "show":
        System.out.println("show\n\nshows the current update packet\n");
        break;
      case "sleep":
        System.out.println("sleep <milliseconds>\n\npause for interval before next command\n");
        break;
      case "tcp":
        System.out.println("tcp\n\nTCP should be used to send all messages\n");
        break;
      case "ttl":
        System.out.println("ttl <ttl>\n\ndefault ttl of added records (default: 0)\n");
        break;
      case "zone":
      case "origin":
        System.out.println("zone <zone>\n\nzone to update (default: .\n");
        break;
      case "#":
        System.out.println("# <text>\n\na comment\n");
        break;
      default:
        System.out.println("Topic '" + topic + "' unrecognized\n");
        break;
    }
  }

  public static void main(String[] args) {

    InputStream in = null;
    if (args.length >= 1) {
      try {
        in = new FileInputStream(args[0]);
      } catch (FileNotFoundException e) {
        System.out.println(args[0] + " not found.");
        System.exit(1);
      }
    } else {
      in = System.in;
    }
    new update(in);
  }
}

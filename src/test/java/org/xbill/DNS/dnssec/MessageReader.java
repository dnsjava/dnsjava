// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

class MessageReader {
  Message readMessage(Reader in) throws IOException {
    BufferedReader r;
    if (in instanceof BufferedReader) {
      r = (BufferedReader) in;
    } else {
      r = new BufferedReader(in);
    }

    Message m = null;
    String line = null;
    int section = 103;
    while ((line = r.readLine()) != null) {
      String[] data;
      if (line.startsWith(";; ->>HEADER<<- ")) {
        section = 101;
        m = new Message();
      } else if (line.startsWith(";; QUESTIONS:")) {
        section = 102;
      } else if (line.startsWith(";; ANSWERS:")) {
        section = Section.ANSWER;
        line = r.readLine();
      } else if (line.startsWith(";; AUTHORITY RECORDS:")) {
        section = Section.AUTHORITY;
        line = r.readLine();
      } else if (line.startsWith(";; ADDITIONAL RECORDS:")) {
        section = 100;
      } else if (line.startsWith("####")) {
        return m;
      } else if (line.startsWith("#")) {
        continue;
      }

      switch (section) {
        case 100: // ignore
          break;

        case 101: // header
          section = 100;
          data = line.substring(";; ->>HEADER<<- ".length()).split(",");
          m.getHeader().setRcode(Rcode.value(data[1].split(":\\s*")[1]));
          m.getHeader().setID(Integer.parseInt(data[2].split(":\\s*")[1]));
          break;

        case 102: // question
          line = r.readLine();
          data = line.split(",");
          Record q =
              Record.newRecord(
                  Name.fromString(data[0].replaceAll(";;\\s*", "")),
                  Type.value(data[1].split("\\s*=\\s*")[1]),
                  DClass.value(data[2].split("\\s*=\\s*")[1]));
          m.addRecord(q, Section.QUESTION);
          section = 100;
          break;

        default:
          if (line != null && !"".equals(line)) {
            Master ma = new Master(new ByteArrayInputStream(line.getBytes()));
            Record record = ma.nextRecord();
            if (record != null) {
              m.addRecord(record, section);
            }
          }
      }
    }

    r.close();
    return m;
  }
}

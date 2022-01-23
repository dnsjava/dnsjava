// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/** Parser for the RPL unit-test files of unbound. */
class RplParser {
  private final InputStream data;
  private final List<String> algoStrings = new ArrayList<>();

  private enum ParseState {
    Zero,
    Server,
    ENTRY_BEGIN,
    STEP_QUERY,
    STEP_CHECK_ANSWER
  }

  RplParser(InputStream data) {
    this.data = data;
    for (Field f : Algorithm.class.getFields()) {
      this.algoStrings.add(f.getName());
    }
  }

  Rpl parse() throws ParseException, IOException {
    BufferedReader r = new BufferedReader(new InputStreamReader(data));
    String line;
    ParseState state = ParseState.Zero;
    Rpl rpl = new Rpl();
    Message m = null;
    int section = -1;
    int step = -1;
    Check check = null;

    while ((line = r.readLine()) != null) {
      // comment or empty
      if (line.equals("") || line.startsWith(";")) {
        continue;
      }

      switch (state) {
        case Zero:
          if (line.startsWith("server:")) {
            state = ParseState.Server;
          } else if (line.startsWith("SCENARIO_BEGIN")) {
            rpl.scenario = line.substring(line.indexOf(" "));
            rpl.replays = new LinkedList<>();
            rpl.checks = new TreeMap<>();
          } else if (line.startsWith("ENTRY_BEGIN")) {
            state = ParseState.ENTRY_BEGIN;
            m = new Message();
          } else if (line.startsWith("STEP")) {
            String[] data = line.split("\\s");
            step = Integer.parseInt(data[1]);
            m = new Message();
            r.readLine();
            if (data[2].equals("QUERY")) {
              state = ParseState.STEP_QUERY;
              check = new Check();
            } else if (data[2].equals("CHECK_ANSWER")) {
              state = ParseState.STEP_CHECK_ANSWER;
            }
          }

          break;

        case Server:
          if (line.matches("\\s*trust-anchor:.*")) {
            SRRset rrset = new SRRset();
            rrset.setSecurityStatus(SecurityStatus.SECURE);
            rrset.addRR(parseRecord(line.substring(line.indexOf("\"") + 1, line.length() - 1)));
            rpl.trustAnchors.add(rrset);
          } else if (line.matches("\\s*val-override-date:.*")) {
            String date = line.substring(line.indexOf("\"") + 1, line.length() - 1);
            DateTimeFormatter formatter =
                new DateTimeFormatterBuilder()
                    .appendPattern("yyyyMMddHHmmss")
                    .toFormatter()
                    .withZone(ZoneId.of("UTC"));
            rpl.date = LocalDateTime.parse(date, formatter).toInstant(ZoneOffset.UTC);
          } else if (line.matches("\\s*val-nsec3-keysize-iterations:.*")) {
            String[] data = line.substring(line.indexOf("\"") + 1, line.length() - 1).split("\\s");
            if (data.length % 2 != 0) {
              throw new ParseException("val-nsec3-keysize-iterations invalid", 0);
            }

            rpl.nsec3iterations = new TreeMap<>();
            for (int i = 0; i < data.length; i += 2) {
              rpl.nsec3iterations.put(Integer.parseInt(data[i]), Integer.parseInt(data[i + 1]));
            }
          } else if (line.matches("\\s*val-digest-preference:.*")) {
            rpl.digestPreference = line.substring(line.indexOf("\"") + 1, line.length() - 1);
          } else if (line.matches("\\s*harden-algo-downgrade:.*")) {
            rpl.hardenAlgoDowngrade = !"no".equalsIgnoreCase(line.split(":")[1].trim());
          } else if (line.matches("\\s*fake-sha1:.*")) {
            rpl.enableSha1 = "yes".equalsIgnoreCase(line.split(":")[1].trim());
          } else if (line.matches("\\s*fake-dsa:.*")) {
            rpl.enableDsa = "yes".equalsIgnoreCase(line.split(":")[1].trim());
          } else if (line.matches("\\s*bouncycastle:.*")) {
            rpl.loadBouncyCastle = "yes".equalsIgnoreCase(line.split(":")[1].trim());
          } else if (line.startsWith("CONFIG_END")) {
            state = ParseState.Zero;
          }

          break;

        case ENTRY_BEGIN:
        case STEP_CHECK_ANSWER:
        case STEP_QUERY:
          if (line.startsWith("MATCH") || line.startsWith("ADJUST")) {
            // ignore
          } else if (line.startsWith("REPLY")) {
            String[] flags = line.split("\\s");
            if (state != ParseState.STEP_QUERY) {
              m.getHeader().setRcode(Rcode.value(flags[flags.length - 1]));
            }

            for (int i = 1; i < flags.length - (state == ParseState.STEP_QUERY ? 0 : 1); i++) {
              if (flags[i].equals("DO")) {
                // set on the resolver, not on the message
              } else {
                int flag = Flags.value(flags[i]);
                if (flag > -1) {
                  m.getHeader().setFlag(flag);
                } else {
                  throw new ParseException(flags[i] + ": not a Flag", i);
                }
              }
            }
          } else if (line.startsWith("SECTION QUESTION")) {
            section = Section.QUESTION;
          } else if (line.startsWith("SECTION ANSWER")) {
            section = Section.ANSWER;
          } else if (line.startsWith("SECTION AUTHORITY")) {
            section = Section.AUTHORITY;
          } else if (line.startsWith("SECTION ADDITIONAL")) {
            section = Section.ADDITIONAL;
          } else if (line.startsWith("ENTRY_END")) {
            if (state == ParseState.ENTRY_BEGIN) {
              rpl.replays.add(m);
            } else if (state == ParseState.STEP_CHECK_ANSWER) {
              check.response = m;
              rpl.checks.put(step, check);
              check = null;
            } else if (state == ParseState.STEP_QUERY) {
              check.query = m;
            }

            m = null;
            state = ParseState.Zero;
          } else {
            Record rec;
            if (section == Section.QUESTION) {
              rec = parseQuestion(line);
            } else {
              rec = parseRecord(line);
            }

            m.addRecord(rec, section);
          }

          break;
      }
    }

    return rpl;
  }

  private Record parseRecord(String line) throws IOException {
    try {
      Master ma = new Master(new ByteArrayInputStream(line.getBytes()), Name.root, 3600);
      Record r = ma.nextRecord();
      if (r.getType() == Type.RRSIG) {
        RRSIGRecord rr = (RRSIGRecord) r;
        // unbound directly uses the DER format for DSA signatures
        // instead of the format specified in rfc2536#section-3
        if (rr.getAlgorithm() == Algorithm.DSA && rr.getSignature().length > 41) {
          Method dsaSignatureToDNS =
              DNSSEC.class.getDeclaredMethod(
                  "dsaSignatureToDNS", byte[].class, int.class, int.class);
          dsaSignatureToDNS.setAccessible(true);
          byte[] signature = (byte[]) dsaSignatureToDNS.invoke(null, rr.getSignature(), 20, 0);
          RRSIGRecord fixed =
              new RRSIGRecord(
                  rr.getName(),
                  rr.getDClass(),
                  rr.getTTL(),
                  rr.getTypeCovered(),
                  rr.getAlgorithm(),
                  rr.getOrigTTL(),
                  rr.getExpire(),
                  rr.getTimeSigned(),
                  rr.getFootprint(),
                  rr.getSigner(),
                  signature);
          Field f = getField(RRSIGRecord.class, "labels");
          f.setAccessible(true);
          f.set(fixed, rr.getLabels());
          r = fixed;
        }
      }

      return r;
    } catch (Exception ex) {
      if (ex.getMessage() != null && ex.getMessage().contains("expected an integer")) {
        String[] data = line.split("\\s");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
          if (this.algoStrings.contains(data[i])) {
            sb.append(Algorithm.value(data[i]));
          } else {
            sb.append(data[i]);
          }
          sb.append(' ');
        }

        return parseRecord(sb.toString());
      } else {
        throw new IOException(line, ex);
      }
    }
  }

  private static Field getField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
    try {
      return clazz.getDeclaredField(fieldName);
    } catch (NoSuchFieldException e) {
      Class<?> superClass = clazz.getSuperclass();
      if (superClass == null) {
        throw e;
      } else {
        return getField(superClass, fieldName);
      }
    }
  }

  private Record parseQuestion(String line) throws TextParseException {
    String[] temp = line.replaceAll("\\s+", " ").split(" ");
    if (Type.value(temp[2]) == -1) {
      System.out.println(temp[2]);
    }

    return Record.newRecord(Name.fromString(temp[0]), Type.value(temp[2]), DClass.value(temp[1]));
  }
}

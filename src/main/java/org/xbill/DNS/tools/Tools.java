// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS.tools;

public class Tools {
  public static void main(String[] args) throws Exception {
    if (args == null || args.length == 0) {
      System.out.println("Usage: <command> <options>");
      System.out.println("  Commands:");
      System.out.println("    dig");
      System.out.println("    jnamed");
      System.out.println("    lookup");
      System.out.println("    primary");
      System.out.println("    update");
      System.out.println("    xfrin");
      System.exit(1);
      return;
    }

    String program = args[0];
    String[] programArgs = new String[args.length - 1];
    System.arraycopy(args, 1, programArgs, 0, args.length - 1);
    switch (program) {
      case "dig":
        dig.main(programArgs);
        break;
      case "jnamed":
        jnamed.main(programArgs);
        break;
      case "lookup":
        lookup.main(programArgs);
        break;
      case "primary":
        primary.main(programArgs);
        break;
      case "update":
        update.main(programArgs);
        break;
      case "xfrin":
        xfrin.main(programArgs);
        break;
      default:
        System.out.println("invalid command");
        break;
    }
  }
}

// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

import org.xbill.DNS.*;

/** @author Brian Wellington &lt;bwelling@xbill.org&gt; */

public class lookup {

public static void
printAnswer(String name, Lookup lookup) {
	System.out.print(name + ":");
	int result = lookup.getResult();
	if (result != Lookup.SUCCESSFUL)
		System.out.print(" " + lookup.getErrorString());
	System.out.println();
	Name [] aliases = lookup.getAliases();
	if (aliases.length > 0) {
		System.out.print("# aliases: ");
		for (int i = 0; i < aliases.length; i++) {
			System.out.print(aliases[i]);
			if (i < aliases.length - 1)
				System.out.print(" ");
		}
		System.out.println();
	}
	if (lookup.getResult() == Lookup.SUCCESSFUL) {
		Record [] answers = lookup.getAnswers();
		for (int i = 0; i < answers.length; i++)
			System.out.println(answers[i]);
	}
}

public static void
main(String [] args) throws Exception {
	int type = Type.A;
	int start = 0;
	if (args.length > 2 && args[0].equals("-t")) {
		type = Type.value(args[1]);
		if (type < 0)
			throw new IllegalArgumentException("invalid type");
		start = 2;
	}
	for (int i = start; i < args.length; i++) {
		Lookup l = new Lookup(args[i], type);
		l.run();
		printAnswer(args[i], l);
	}
}

}

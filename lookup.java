import java.util.*;
import org.xbill.DNS.*;

public class lookup {

public static void
printAnswer(String name, Lookup lookup) {
	System.out.print(name + ":");
	if (lookup.getResult() == Lookup.SUCCESSFUL) {
		System.out.println();
		Record [] answers = lookup.getAnswers();
		for (int i = 0; i < answers.length; i++)
			System.out.println(answers[i]);
	} else {
		 System.out.println(" " + lookup.getErrorString());
	}
}

public static void
main(String [] args) throws Exception {
	short type = Type.A;
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

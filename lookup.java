import java.util.*;
import org.xbill.DNS.*;

public class lookup {

public static void
printAnswer(String name, Lookup lookup) {
	System.out.print(name + ":");
	int result = lookup.getResult();
	if (result != Lookup.SUCCESSFUL)
		System.out.print(" " + lookup.getErrorString());
	System.out.println();
	if (lookup.getResult() == Lookup.SUCCESSFUL) {
		Record [] answers = lookup.getAnswers();
		for (int i = 0; i < answers.length; i++)
			System.out.println(answers[i]);
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

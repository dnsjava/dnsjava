import java.util.*;
import org.xbill.DNS.*;

public class lookup {

public static void
printAnswer(String name, Record [] answer) {
	System.out.println(name + ":");
	if (answer == null)
		System.out.println("null");
	else
		for (int i = 0; i < answer.length; i++)
			System.out.println(answer[i]);
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
	for (int i = start; i < args.length; i++)
		printAnswer(args[i], dns.getRecords(args[i], type));
}

}

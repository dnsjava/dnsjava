import java.util.Hashtable;

public class dnsCompression {

Hashtable h;

public dnsCompression() {
	h = new Hashtable();
}

public void add(int pos, dnsName name) {
	h.put (new Integer(pos), name);
}

public dnsName get(int pos) {
	return (dnsName)h.get(new Integer(pos));
}

}

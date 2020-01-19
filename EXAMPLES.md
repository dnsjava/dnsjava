# dnsjava Examples

All of these examples are code fragments. Code using these fragments should
check exceptions when appropriate, and should:

```java
import org.xbill.DNS.*;
```

## Get the IP address associated with a name

```java
InetAddress addr = Address.getByName("www.dnsjava.org");
```

## Get the MX target and preference of a name

```java
Record[] records = new Lookup("gmail.com", Type.MX).run();
for (int i = 0; i < records.length; i++) {
    MXRecord mx = (MXRecord) records[i];
    System.out.println("Host " + mx.getTarget() + " has preference " + mx.getPriority());
}
```

## Query a remote name server for its version

```java
Lookup l = new Lookup("version.bind.", Type.TXT, DClass.CH);
l.setResolver(new SimpleResolver(args[0]));
l.run();
if (l.getResult() == Lookup.SUCCESSFUL) {
    System.out.println(l.getAnswers()[0].rdataToString());
}
```

## Transfer a zone from a server and print it

```java
ZoneTransferIn xfr = ZoneTransferIn.newAXFR(Name.root, "192.5.5.241", null);
List records = xfr.run();
for (Iterator it = records.iterator(); it.hasNext();) {
    System.out.println(it.next());
}
```

## Use DNS dynamic update to set the address of a host to a value specified on the command line

```java
Name zone = Name.fromString("dyn.test.example.");
Name host = Name.fromString("host", zone);
Update update = new Update(zone);
update.replace(host, Type.A, 3600, args[0]);

Resolver res = new SimpleResolver("10.0.0.1");
res.setTSIGKey(new TSIG(host, base64.fromString("1234")));
res.setTCP(true);

Message response = res.send(update);
```

## Manipulate domain names

```java
Name n = Name.fromString("www.dnsjava.org");
Name o = Name.fromString("dnsjava.org");
System.out.println(n.subdomain(o));            // True

System.out.println(n.compareTo(o));            // > 0

Name rel = n.relativize(o);                    // the relative name 'www'
Name n2 = Name.concatenate(rel, o);
System.out.println(n2.equals(n));              // True

// www
// dnsjava
// org
for (int i = 0; i < n.labels(); i++) {
    System.out.println(n.getLabelString(i));
}
```

JAVAC=javac
JFLAGS=-g

JAVADOC=javadoc -d doc -windowtitle "dnsjava documentation" -link http://java.sun.com/products/jdk/1.2/docs/api

all:
	${JAVAC} ${JFLAGS} *.java org/xbill/Task/*.java org/xbill/DNS/*.java org/xbill/DNS/utils/*.java

dnssec:
	${JAVAC} ${JFLAGS} org/xbill/DNS/security/*.java

clean:
	rm -f *.class org/xbill/Task/*.class org/xbill/DNS/*.class org/xbill/DNS/utils/*.class org/xbill/DNS/security/*.class

docs:
	if test ! -d doc ; then mkdir doc ; fi
	${JAVADOC} org.xbill.Task org.xbill.DNS org.xbill.DNS.utils org.xbill.DNS.security

docsclean:	
	rm -rf doc/*

JAVAC=jikes
JFLAGS=-g

JAVADOC=/usr/local/jdk1.2/bin/javadoc -d doc -windowtitle "dnsjava documentation" -link http://java.sun.com/products/jdk/1.2/docs/api

all:
	${JAVAC} ${JFLAGS} *.java DNS/*.java DNS/utils/*.java

clean:
	rm -f *.class DNS/*.class DNS/utils/*.class

docs:
	if test ! -d doc ; then mkdir doc ; fi
	${JAVADOC} DNS DNS.utils

docsclean:	
	rm -f doc/*

JAVAC=jikes
JFLAGS=-g

JAVADOC=/usr/local/jdk1.2/bin/javadoc -d doc

all:
	${JAVAC} ${JFLAGS} *.java DNS/*.java DNS/utils/*.java

clean:
	rm -f *.class DNS/*.class DNS/utils/*.class

docs:
	if test ! -d doc ; then mkdir doc ; fi
	${JAVADOC} DNS DNS.utils

docsclean:	
	rm -f doc/*

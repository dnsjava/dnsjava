JAVAC=jikes
JFLAGS=-g
JAVADOC=/usr/local/jdk1.2/bin/javadoc -d doc

all:
	${JAVAC} ${JFLAGS} *.java DNS/*.java DNS/utils/*.java

clean:
	rm -f *.class DNS/*.class DNS/utils/*.class

docs:
	${JAVADOC} DNS DNS.utils

docsclean:	
	rm -f doc/*

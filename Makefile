JAVAC=javac
JFLAGS=-g

all:
	${JAVAC} ${JFLAGS} *.java DNS/*.java DNS/utils/*.java

clean:
	rm -f *.class DNS/*.class DNS/utils/*.class

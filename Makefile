JAVAC=javac
JFLAGS=-g

all:
	${JAVAC} ${JFLAGS} *.java DNS/*.java

clean:
	rm -f *.class DNS/*.class

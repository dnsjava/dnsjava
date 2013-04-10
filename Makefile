JAVAC = javac
JFLAGS = -g
JAR = jar cf

SUNAPIDOC = http://java.sun.com/j2se/1.4/docs/api
JAVADOC=javadoc -classpath . -d doc -windowtitle "dnsjava documentation" -link ${SUNAPIDOC}

VERSION = 2.1.5

DNSSRC = org/xbill/DNS/*.java \
	 org/xbill/DNS/utils/*.java
PROGSRC = *.java

DNSCLASS = org/xbill/DNS/*.class \
	   org/xbill/DNS/utils/*.class
PROGCLASS = *.class

CLASSLIST = org.xbill.DNS org.xbill.DNS.utils

JARFILE = dnsjava-${VERSION}.jar

all:
	${JAVAC} ${JFLAGS} ${PROGSRC} ${DNSSRC}

jar:
	${JAR} ${JARFILE} ${PROGCLASS} ${DNSCLASS}

clean:
	rm -f ${PROGCLASS} ${DNSCLASS} ${JARFILE}

doc docs: docsclean
	if test ! -d doc ; then mkdir doc ; fi
	${JAVADOC} ${CLASSLIST}

docclean docsclean:	
	rm -rf doc/*

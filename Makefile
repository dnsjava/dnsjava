JAVAC = javac
JFLAGS = -g
JAR = jar cf

SUNAPIDOC = http://java.sun.com/j2se/1.4/docs/api
JAVADOC=javadoc -classpath . -d doc -windowtitle "dnsjava documentation" -link ${SUNAPIDOC}

VERSION = 2.0.5

DNSSRC = org/xbill/DNS/*.java \
	 org/xbill/DNS/utils/*.java \
	 org/xbill/DNS/security/*.java
PROGSRC = *.java

DNSCLASS = org/xbill/DNS/*.class \
	   org/xbill/DNS/utils/*.class \
	   org/xbill/DNS/security/*.class
PROGCLASS = *.class

CLASSLIST = org.xbill.DNS org.xbill.DNS.utils org.xbill.DNS.security

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

JAVAC = javac
JFLAGS = -g
JAR = jar cf

SUNAPIDOC = http://java.sun.com/products/jdk/1.4/docs/api
JAVADOC=javadoc -classpath . -d doc -windowtitle "dnsjava documentation" -link ${SUNAPIDOC}

VERSION = 1.3.2

DNSSRC = org/xbill/DNS/*.java org/xbill/DNS/utils/*.java
DNSSECSRC = org/xbill/DNS/security/*.java
PROGSRC = *.java

DNSCLASS = org/xbill/DNS/*.class org/xbill/DNS/utils/*.class
DNSSECCLASS = org/xbill/DNS/security/*.class
PROGCLASS = *.class

CLASSLIST = org.xbill.DNS org.xbill.DNS.utils org.xbill.DNS.security

JARFILE = dnsjava-${VERSION}.jar

all:
	${JAVAC} ${JFLAGS} ${PROGSRC} ${DNSSRC}

dnssec:
	${JAVAC} ${JFLAGS} ${DNSSECSRC}

jar:
	${JAR} ${JARFILE} ${PROGCLASS} ${DNSCLASS} ${DNSSECCLASS}

clean:
	rm -f ${PROGCLASS} ${DNSCLASS} ${DNSSECCLASS} ${JARFILE}

doc docs: docsclean
	if test ! -d doc ; then mkdir doc ; fi
	${JAVADOC} ${CLASSLIST}

docclean docsclean:	
	rm -rf doc/*

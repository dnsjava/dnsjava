all:
	jikes -g *.java DNS/*.java

clean:
	rm -f *.class DNS/*.class

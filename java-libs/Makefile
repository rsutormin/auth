VER := $(shell git rev-parse --short HEAD)

EPOCH := $(shell date +%s)

AUTH-JAR = kbase-auth-$(EPOCH)-$(VER).jar

all: compile-java test-java

compile-java:
	cd src/; \
	javac -cp ../lib/jackson-annotations-2.2.3.jar:../lib/jackson-core-2.2.3.jar:../lib/jackson-databind-2.2.3.jar us/kbase/auth/*.java; \
	jar cvf ../$(AUTH-JAR) us/kbase/auth/*.class

test-java: compile-java
	@read -p "Enter password for test user 'kbasetest': " pwd; \
	javac -cp $(AUTH-JAR):lib/jackson-annotations-2.2.3.jar:lib/jackson-core-2.2.3.jar:lib/jackson-databind-2.2.3.jar:test:test/lib/junit-4.10.jar test/AuthServiceTest.java; \
	java -cp $(AUTH-JAR):lib/jackson-annotations-2.2.3.jar:lib/jackson-core-2.2.3.jar:lib/jackson-databind-2.2.3.jar:test:test/lib/junit-4.10.jar \
		-Dtest.user.password=$$pwd org.junit.runner.JUnitCore AuthServiceTest
		

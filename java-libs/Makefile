VER = $(shell git rev-parse --short HEAD)

all: compile-java test-java

compile-java:
	cd src/; \
	javac -cp ../lib/jackson-annotations-2.2.3.jar:../lib/jackson-core-2.2.3.jar:../lib/jackson-databind-2.2.3.jar us/kbase/auth/*.java; \
	jar cvf ../kbase-auth-$(VER).jar us/kbase/auth/*.class

test-java:
	@read -p "Enter password for test user 'kbasetest': " pwd; \
	javac -cp kbase-auth-$(VER).jar:lib/jackson-annotations-2.2.3.jar:lib/jackson-core-2.2.3.jar:lib/jackson-databind-2.2.3.jar:test:test/lib/junit-4.10.jar test/AuthServiceTest.java; \
	java -cp kbase-auth-$(VER).jar:lib/jackson-annotations-2.2.3.jar:lib/jackson-core-2.2.3.jar:lib/jackson-databind-2.2.3.jar:test:test/lib/junit-4.10.jar \
		-Dtest.user.password=$$pwd org.junit.runner.JUnitCore AuthServiceTest
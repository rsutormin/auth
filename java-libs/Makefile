VER = $(shell git rev-parse --short HEAD)

all: compile-java test-java

compile-java:
	cd src/; \
	javac -cp ../lib/jackson-all-1.9.11.jar us/kbase/auth/*.java; \
	jar cvf ../kbase-auth-$(VER).jar us/kbase/auth/*.class

test-java:
	@read -p "Enter password for test user 'kbasetest': " pwd; \
	javac -cp kbase-auth-$(VER).jar:lib/jackson-all-1.9.11.jar:test:test/lib/junit-4.10.jar test/AuthServiceTest.java; \
	java -cp kbase-auth-$(VER).jar:lib/jackson-all-1.9.11.jar:test:test/lib/junit-4.10.jar \
		-Dtest.user.password=$$pwd org.junit.runner.JUnitCore AuthServiceTest
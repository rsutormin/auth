all: compile-java test-java

compile-java:
	cd src/; \
	javac -cp ../lib/bcpkix-jdk15on-147.jar:../lib/bcprov-ext-jdk15on-147.jar:../lib/jackson-all-1.9.11.jar us/kbase/auth/*.java; \
	jar cvf ../kbase-auth.jar us/kbase/auth/*.class

test-java:
	@read -p "Enter password for test user 'kbasetest': " -s pwd; \
	javac -cp kbase-auth.jar:lib/bcpkix-jdk15on-147.jar:lib/bcprov-ext-jdk15on-147.jar:lib/jackson-all-1.9.11.jar:test:test/lib/junit-4.10.jar test/AuthServiceTest.java; \
	java -cp kbase-auth.jar:lib/bcpkix-jdk15on-147.jar:lib/bcprov-ext-jdk15on-147.jar:lib/jackson-all-1.9.11.jar:test:test/lib/junit-4.10.jar \
		-Dtest.user.password=$$pwd org.junit.runner.JUnitCore AuthServiceTest
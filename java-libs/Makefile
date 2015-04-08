ANT = ant

VER := $(shell git rev-parse --short HEAD)

EPOCH := $(shell date +%s)

FINAL_VER := $(shell python translate_version.py $(VER) $(EPOCH))

AUTH-JAR = kbase-auth-$(FINAL_VER).jar

all: test-java

compile-java:
	$(ANT) compile -Dcompile.jarfile=$(AUTH-JAR)

test-java:
	@# ant runs compile for the test target
	@read -p "Enter password for test user 'kbasetest': " pwd; \
	$(ANT) test -Dcompile.jarfile=$(AUTH-JAR) -Dtest.user.password=$$pwd
		

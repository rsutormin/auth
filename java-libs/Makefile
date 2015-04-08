JAR-PREFIX = kbase-auth

ANT = ant

GITCOMMIT := $(shell git rev-parse --short HEAD)
EPOCH := $(shell date +%s)
#TODO use --points-at vs. --contains when git 1.7.10 available
TAGS := $(shell git tag --contains $(GITCOMMIT))
TAG := $(shell python checktags.py $(TAGS))

ERR := $(findstring Two valid tags for this commit, $(TAG))

ifneq ($(ERR), )
$(error Tags are ambiguous for this commit: $(TAG))
endif 

AUTH-JAR = $(JAR-PREFIX)-$(TAG).jar

ifeq ($(TAG), )
AUTH-JAR = $(JAR-PREFIX)-$(EPOCH)-$(GITCOMMIT).jar
endif

all: test-java javadoc

compile-java:
	$(ANT) compile -Dcompile.jarfile=$(AUTH-JAR)
	
javadoc:
	$(ANT) javadoc

test-java:
	@# ant runs compile for the test target
	@read -p "Enter password for test user 'kbasetest': " pwd; \
	$(ANT) test -Dcompile.jarfile=$(AUTH-JAR) -Dtest.user.password=$$pwd
		

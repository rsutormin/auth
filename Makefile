TOP_DIR = ../..
include $(TOP_DIR)/tools/Makefile.common

SRC_PERL = $(wildcard scripts/*.pl)
BIN_PERL = $(addprefix $(BIN_DIR)/,$(basename $(notdir $(SRC_PERL))))
LIB_PERL = $(wildcard Bio-KBase-Auth/lib/Bio/KBase/*.pm)


DEPLOY_RUNTIME ?= /kb/runtime
TARGET ?= /kb/deployment
DEPLOY_PERL = $(addprefix $(TARGET)/bin/,$(basename $(notdir $(SRC_PERL))))

#KB_PERL_PATH = $(DEPLOY_RUNTIME)/perl5/site_perl
KB_PERL_PATH = $(TARGET)/lib

SERVICE = authorization_server
SERVICE_DIR = $(TARGET)/services/$(SERVICE)


all: deploy

deploy: install-libs

install-libs:
	cd Bio-KBase-Auth; \
	mkdir -p $(KB_PERL_PATH); \
	/kb/runtime/bin/perl ./Build.PL ; \
	/kb/runtime/bin/perl ./Build installdeps --install_path lib=$(KB_PERL_PATH); \
	/kb/runtime/bin/perl ./Build install --install_path lib=$(KB_PERL_PATH) ;

test: test-libs

test-libs: install-libs
	export PERL5LIB=$(KB_PERL_PATH) ; \
	cd Bio-KBase-Auth; /kb/runtime/bin/perl ./Build test;

deploy-doc:
	-mkdir  $(TARGET)/services
	-mkdir  $(SERVICE_DIR)

	# run each perl module
	for l in $(LIB_PERL) ; do \
	name=$$(basename $$l pm) ; \
	echo $$n ; \
		if [ -f $$l ] ; then \
			$(DEPLOY_RUNTIME)/bin/pod2html -t $(SERVICE) $$l > docs/$$name.html ; \
			if [ $$? -ne 0 ] ; then \
				exit 1 ; \
			fi \
		fi \
	done

	cp docs/*html $(SERVICE_DIR)/webroot/.

	

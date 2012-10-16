TOP_DIR = ../..
include $(TOP_DIR)/tools/Makefile.common

SRC_PERL = $(wildcard scripts/*.pl)
BIN_PERL = $(addprefix $(BIN_DIR)/,$(basename $(notdir $(SRC_PERL))))

DEPLOY_PERL = $(addprefix $(TARGET)/bin/,$(basename $(notdir $(SRC_PERL))))

TARGET ?= /kb/deployment
KB_PERL_PATH = $(TARGET)

all:

deploy: install-libs

install-libs:
	cd Bio-KBase-Auth; \
	mkdir -p $(KB_PERL_PATH); \
	/kb/runtime/bin/perl ./Build.PL ; \
	/kb/runtime/bin/perl ./Build installdeps --install_base $(KB_PERL_PATH); \
	/kb/runtime/bin/perl ./Build install --install_base $(KB_PERL_PATH) ;

test-libs: install-libs
	export PERL5LIB=$(KB_PERL_PATH) ; \
	cd Bio-KBase-Auth; /kb/runtime/bin/perl ./Build test;

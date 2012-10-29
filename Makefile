TOP_DIR = ../..
include $(TOP_DIR)/tools/Makefile.common

SRC_PERL = $(wildcard scripts/*.pl)
BIN_PERL = $(addprefix $(BIN_DIR)/,$(basename $(notdir $(SRC_PERL))))

DEPLOY_RUNTIME ?= /kb/runtime
TARGET ?= /kb/deployment
DEPLOY_PERL = $(addprefix $(TARGET)/bin/,$(basename $(notdir $(SRC_PERL))))

KB_PERL_PATH = $(DEPLOY_RUNTIME)/perl5/site_perl

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

test-libs: install-libs
	export PERL5LIB=$(KB_PERL_PATH) ; \
	cd Bio-KBase-Auth; /kb/runtime/bin/perl ./Build test;

TOP_DIR = ../..
include $(TOP_DIR)/tools/Makefile.common

SRC_PERL = $(wildcard scripts/*.pl)
BIN_PERL = $(addprefix $(BIN_DIR)/,$(basename $(notdir $(SRC_PERL))))

DEPLOY_PERL = $(addprefix $(TARGET)/bin/,$(basename $(notdir $(SRC_PERL))))

TARGET ?= /kb/deployment
KB_PERL_PATH = $(TARGET)/lib

SERVICE = authorization_service
SERVICE_DIR = $(TARGET)/services/$(SERVICE)
NGINX_CONF = /etc/nginx/conf.d/

all:

deploy: install-libs

install-libs:
	cd Bio-KBase-Auth; \
	mkdir -l $(KB_PERL_PATH); \
	/kb/runtime/bin/perl ./Build.PL ; \
	/kb/runtime/bin/perl ./Build installdeps --install_base $(KB_PERL_PATH); \
	/kb/runtime/bin/perl ./Build install --install_base $(KB_PERL_PATH) ;

test-libs: install-libs
	export PERL5LIB=$(KB_PERL_PATH) ; \
	cd Bio-KBase-Auth; /kb/runtime/bin/perl ./Build test;

deploy-nginx:
	cp nginx.conf $(NGINX_CONF)/$(SERVICE).conf
	service nginx restart || echo "Already Up"

deploy-services:
	mkdir -p $(SERVICE_DIR)
	rsync -avz --exclude .git *.py start_service stop_service test_service job_service $(SERVICE_DIR)
	cat config.ini.sample |sed "s/XXXXXX/$(RMQ_PASS)/" > $(SERVICE_DIR)/config.ini
	cd $(SERVICE_DIR);echo no|python ./manage.py syncdb


SERVICE = auth_server
SERVICE_DIR = $(TARGET)/services/$(SERVICE)
NGINX_CONF = /etc/nginx/conf.d/
TARGET ?= /kb/deployment

all:

deploy: install-libs

install-libs:
	cd Bio-KBase-Auth; /kb/runtime/bin/perl ./Build.PL; /kb/runtime/bin/perl ./Build installdeps; /kb/runtime/bin/perl ./Build install; 


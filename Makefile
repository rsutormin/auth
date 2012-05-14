SERVICE = auth_server
SERVICE_DIR = $(TARGET)/services/$(SERVICE)
NGINX_CONF = /etc/nginx/conf.d/
TARGET ?= /kb/deployment

all:

deploy: deploy-services deploy-nginx install-libs

deploy-nginx:
	cp nginx.conf $(NGINX_CONF)/$(SERVICE).conf
	service nginx restart || echo "Already Up"

deploy-services:
	mkdir -p $(SERVICE_DIR)
	rsync -avz --exclude .git --cvs-exclude directory_server start_service stop_service django.conf var $(SERVICE_DIR)
	cd $(SERVICE_DIR)/directory_server;echo no|python ./manage.py syncdb

install-libs:
	cd Bio-KBase-Auth; /kb/runtime/bin/perl ./Build.PL; /kb/runtime/bin/perl ./Build install


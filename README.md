### Dependencies

* External Package

* Required Perl libs (install using cpan)
    * Object::Tiny::RW
    * JSON
    * REST::Client
    * Digest::SHA1
    * Crypt::OpenSSL::RSA
    * Crypt::OpenSSL::X509
    * URI::Escape
    * URI::QueryParam
    * MIME::Base64
    * HTTP::Request
    * HTTP::Daemon
    * LWP::UserAgent
    * Net::OAuth
    * URI::Escape
    * Carp
    * Data::Dumper
    * Test::More
    * Crypt::SSLeay
    * Test::Deep::NoTest
    * Storable
    * Email::Valid

* Required Python libs (install using easy_install or pip)

    * certifi==0.0.8
    * chardet==1.0.1
    * distribute==0.6.24
    * oauthlib==0.1.3
    * pyasn1==0.1.3
    * requests==0.13.0
    * rsa==3.0.1
    * pyyaml==3.10
    * httplib2==0.7.1
    * oauth2==1.5.167
    * pymongo==2.3
    * django==1.4.1
    * django_piston==0.2.2

* Ports that need to be open

### Google Doc for API

   Perl libraries have built in perldocs. The authentication libraries use
Globus Online's Nexus service for authentication. User accounts can be
registered at:

https://www.globusonline.org/SignUp

   There is a developer tutorial at:

http://www.kbase.us/developer-zone/tutorials/developer-tutorials/kbase-authentication/

   The initial documentation for the authorization service is here:

https://docs.google.com/document/d/1CTkthDUPwNzMF22maLyNIktI1sHdWPwtd3lJk0aFb20/edit

   Going to http://{authorization.host}/Roles will being up a JSON document that
gives a description of the service.

### Setup using the kbase VMs
=======
0.  Start the VM and clone the git repo.
    nova boot .... (options will change over time)
    ssh ubuntu@<vm host>
    git clone ssh://kbase@git.kbase.us/auth
    cd auth

1. As root do a make deploy. This will install the perl libraries
   sudo -s
   make deploy 

2. Run tests for the perl libraries
   sudo make test-libs

3. The make target deploy-services will install and configure the authorization service
   sudo make deploy-services

4. To configure the mongodb instance used to back the authorization service, create a
file authorization_server/authorization_server/local_settings.py that declares which
mongodb service to use. If there is no local_settings file the service will default to
a localhost instance on the default port. In production you should have something like
this example:
cat /kb/deployment/services/authorization_server/authorization_server/authorization_server/local_settings.py
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': os.path.join(os.path.dirname(__file__), 'dbfiles/authdb.db'), # Or path to database file if using sqlite3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}

MONGODB_CONN = ['mongodb.kbase.us']

5. If necessary, you can load the base/bootstrap authorization roles by using the "load-mongodb" target to initialize the mongodb service with a bare minimum set of roles. This is not necessary when working with the mongodb.kbase.us service.
   sudo make load-mongodb

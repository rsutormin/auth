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

### Google Doc for API

   Perl libraries have built in perldocs. The authentication libraries use
Globus Online's Nexus service for authentication. User accounts can be
registered at:

https://www.globusonline.org/SignUp

   There is a developer tutorial at:

http://www.kbase.us/developer-zone/tutorials/developer-tutorials/kbase-authentication/

   The initial documentation for the authorization service is here:

https://docs.google.com/document/d/1CTkthDUPwNzMF22maLyNIktI1sHdWPwtd3lJk0aFb20/edit

   Going to http://{authorization.host}/Roles?about will being up a JSON document that
gives a description of the service.
   The file authorization_service/authorization_service/handlers.py implements the
REST service, and had a largish comment at the top explaining how it works.
   Unittests for the authz service have been implemented using the Django unittest
framework, so they can be run with "manage.py test authorization_server"

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
   make test-libs

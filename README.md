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

* Ports that need to be open

### Google Doc for API

   There is a Google Doc that can be accessed at this URL:

https://docs.google.com/a/lbl.gov/document/d/1R3PSQbeR3EGpigupzGnua4qdBXpVjBQ-rQ0NBp3p6xY/edit#

   Over time, all information in that document wll be migrated into perldocs and it will be superfluous

   To create accounts, please use this URL and register any accounts you need:

   https://test.globuscs.info/

### Setup using the kbase VMs
=======
0.  Start the VM and clone the git repo.
    nova boot .... (options will change over time)
    ssh ubuntu@<vm host>
    git clone ssh://kbase@git.kbase.us/auth
    cd auth

1. As root do a make deploy.  This will configure the rabbit service and initialize the service database.
   sudo -s
   make deploy 

   If you are not installing the directory service, you can simply run "make install-libs" and the
   makefile will install the Perl libraries

4. Run tests
   sudo make test-libs

      

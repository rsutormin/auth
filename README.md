### Dependencies

* External Package

* Required Perl libs (install using cpan)
    * Object::Tiny::RW
    * JSON
    * REST::Client
    * Digest::SHA
    * Digest::MD5
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
   Load the testdata for the python instance
      cd (git working directory for auth module)
      cd Bio-KBase-Auth
      /kb/runtime/bin/perl ./Build test

      

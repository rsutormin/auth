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

### Setup using the kbase VMs
=======
0.  Start the VM and clone the git repo.
    nova boot .... (options will change over time)
    ssh ubuntu@<vm host>

1. Following an updated version of the directions
   from: https://trac.kbase.us/projects/kbase/wiki/IntegrationTargets
   sudo bash
   cd /kb
   git clone kbase@git.kbase.us:/dev_container.git
   cd dev_container/modules
   git clone kbase@git.kbase.us:/auth.git
   cd ..
   ./bootstrap /kb/runtime
   . user-env.sh

2. As root do a make deploy. This will install the perl libraries
   cd modules/auth
   make deploy 

3. Run tests for the perl libraries
   make test

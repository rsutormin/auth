### Dependencies

* External Package
    * mysql

* Required Python libs (install using `easy_install`)
    * django
    * django-piston
    * httplib2
    * south
    * flup

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

* Ports that need to be open
    * django server (default port 8000)

### Setup using the kbase VMs

0.  Start the VM and clone the git repo.
    nova boot .... (options will change over time)
    ssh ubuntu@<vm host>
    git clone ssh://kbase@git.kbase.us/auth
    cd auth

1.  Create a local_settings.py file in directory_server/AuthSvc to point to the local database service.
    Look at sample_DBTYPE_local_settings.py as a template for MySQL and SQLite3 setups.

2. As root do a make deploy.  This will configure the rabbit service and initialize the service database.
   sudo -s
   make deploy 

3. Start the service (as root)
   /kb/deployment/services/cluster_service/start_service

4. Run tests
   Load the testdata for the python instance
      cd (deployment directory)/directory_server
      ./manage.py loaddata utils/test_data.json
   Enter the perl module directory, configure the location of the
   directory server and install the libraries and run the tests
      cd (git working directory for auth module)
      cd Bio-KBase-Auth
      # edit lib/Bio/KBase/Auth.pm and edit the value of
      # $Bio::KBase::Auth::AuthSvcHost to be the URL for the
      # nginx server
      perl Build.PL
      ./Build install
      ./Build test

      

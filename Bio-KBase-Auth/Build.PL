#!/usr/bin/env perl

use Module::Build;
Module::Build->new(
    module_name => 'Bio::KBase::Auth',
    license     => 'perl',
    requires => { 'Object::Tiny::RW' => 1.07,
		  'JSON' => 2.53,
		  'Digest::SHA1' => 2.13,
		  'Crypt::OpenSSL::RSA' => 0.28,
		  'Crypt::OpenSSL::X509' => 0.28,
		  'Convert::PEM' => 0.08,
		  'MIME::Base64' => 3.08,
		  'HTTP::Request' => 6.00,
		  'HTTP::Daemon' => 6.00,
		  'LWP::UserAgent' => 6.02,
		  'URI' => 1.37,
		  'URI::Escape' => 1.60,
		  'URI::QueryParam' => undef,
		  'Carp' => 1.17,
		  'Data::Dumper' => 2.1,
		  'Test::More' => 0.94,
		  'Storable' => 2.22,
		  'Test::Deep' => 0.109,
    },
    dist_abstract => 'Classes to support OAuth based authentication for the Bio::KBase::* libraries',
    )->create_build_script;

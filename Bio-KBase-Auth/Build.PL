#!/usr/bin/env perl

use Module::Build;
Module::Build->new(
    module_name => 'Bio::KBase::Auth',
    license     => 'perl',
    requires => { 'Object::Tiny::RW' => 1.07,
		  'JSON' => 2.53,
		  'Digest::SHA1' => 2.13,
		  'Crypt::OpenSSL::RSA' => 0.28,
		  'Convert::PEM' => 0.08,
		  'MIME::Base64' => 3.08,
		  'HTTP::Request' => 6.00,
		  'HTTP::Daemon' => 6.00,
		  'LWP::UserAgent' => 6.02,
		  'URI' => 1.37,
		  'Test::More' => 0.94,
		  'Test::Deep' => 0.109,
    },
    dist_abstract => 'Classes to support OAuth based authentication for the Bio::KBase::* libraries',
    )->create_build_script;

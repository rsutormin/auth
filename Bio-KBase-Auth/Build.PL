#!/usr/bin/env perl

use Module::Build;
Module::Build->new(
    module_name => 'Bio::KBase::Auth',
    license     => 'perl',
    )->create_build_script;

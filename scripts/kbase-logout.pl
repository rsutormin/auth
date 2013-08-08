#!/usr/bin/env perl
########################################################################
# Adapted from original kbws-logout.pl script from kbase workspace module
# Clears the auth_token and user_id fields from the ~/.kbase_config file
# (or whatever file Bio::KBase::Auth determines is the config file path)
# Steve Chan sychan@lbl.gov
#
# original headers follow:
# Authors: Christopher Henry, Scott Devoid, Paul Frybarger
# Contact email: chenry@mcs.anl.gov
# Development location: Mathematics and Computer Science Division, Argonne National Lab
########################################################################
use strict;
use warnings;
use Bio::KBase::Auth;
Bio::KBase::Auth::SetConfigs( user_id => undef, token => undef);
print "Logged in as:\npublic\n";

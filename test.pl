#!/bin/env perl
#
# Test some basic auth calls
# sychan@lbl.gov
# 5/3/12
#

use lib "libs/";
use Data::Dumper;
use Bio::KBase::AuthDirectory;

my $ad = new Bio::KBase::AuthDirectory;

my $user = $ad->lookup_user('sychan');
print "Results from AuthDirectory::lookup_user('sychan'):\n";
print Dumper( $user);

print "Results from AuthDirectory::lookup_consumer('key1'):\n";
print Dumper( $ad->lookup_consumer('key1'));

print "Results from AuthDirectory::lookup_oauth2_token('token1'):\n";
print Dumper( $ad->lookup_oauth2_token('token1'));

print "Results from AuthDirectory::lookup_oauth2_token('token61'):\n";
print Dumper( $ad->lookup_oauth2_token('token6'));

1;

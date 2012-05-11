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

print "Creating a new user sychan2\n";
$user = new Bio::KBase::AuthUser;
$user->user_id('sychan2');
$user->name('s chan again');
$user->email('sychan2@lbl.gov');

$newuser = $ad->create_user( $user);
if ($newuser) {
    print Dumper( $newuser);
} else {
    printf "Error: %s\n", $ad->error_message;
}

print "Updating user's email field to sychan2@whitehouse.gov\n";
$newuser->email('sychan2@whitehouse.gov');
if ($ad->update_user( $newuser)) {
    print "Success!\n";
    Dumper( $newuser);
} else {
    printf "Error: %s\n", $ad->error_message;
}    
print "Enabling new user\n";
if ( $ad->enable_user('sychan2')) {
    print "Success!\n";
    $user= $ad->lookup_user('sychan2');
    printf "Enabled field = %s\n", $user->enabled();
} else {
    printf "Error: %s\n", $ad->error_message;
}

print "Disabling new user\n";
if ( $newuser = $ad->disable_user('sychan2')) {
    print "Success!\n";
    $user= $ad->lookup_user('sychan2');
    printf "Enabled field = %s\n", $user->enabled();
} else {
    printf "Error: %s\n", $ad->error_message;
}
print "Added a new consumer key\n";

$key = $ad->new_consumer( "sychan2");

if ($key) {
    printf "Success!!\noauth_key:%s\noauth_secret:%s\n", $key->{oauth_key},
    $key->{oauth_secret};
} else {
    printf "Error: %s\n", $ad->error_message;
}

printf "Deleting oauth_key %s\n", $key->{oauth_key};

if ( $ad->delete_consumer( $key->{oauth_key})) {
    printf "Success!!\n";
} else {
    printf "Error: %s\n", $ad->error_message;
}

print "Deleting user sychan2\n";

if ($ad->delete_user('sychan2')) {
    print "Success!\n";
} else {
    printf "Error: %s\n", $ad->error_message;
}

1;

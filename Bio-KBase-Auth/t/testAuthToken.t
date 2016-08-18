#!/usr/bin/env perl
#
# Test the Authentication Token code
#
# sychan@lbl.gov
# 8/13/2012
# kkeller@lbl.gov August 2016

use strict;

use lib "../lib/";

use Test::More tests => 26;

use Config::Simple;

BEGIN {
    no strict;
    use_ok( Bio::KBase::AuthToken);
}

my %testConfig;
Config::Simple->import_from('./test.cfg', \%testConfig);

my @users = ();

if ( defined $ENV{ $Bio::KBase::AuthToken::TokenEnv }) {
    undef $ENV{ $Bio::KBase::AuthToken::TokenEnv };
}

my %old_config = map { $_ =~ s/authentication\.//; $_ => $Bio::KBase::Auth::Conf{'authentication.' . $_ } } keys %Bio::KBase::Auth::AuthConf;

if ( -e $Bio::KBase::Auth::ConfPath) {
    # clear all the authentication fields that we may care about during testing
    my %new = %old_config;
    foreach my $key ( 'user_id','password','keyfile','keyfile_passphrase','client_secret','token') {
	$new{$key} = undef;
    }
    Bio::KBase::Auth::SetConfigs( %new);

}

my $authurl=$testConfig{'auth_test.test.authurl'};
my $authBadUrl='https://auth.invalid';
my $validuser=$testConfig{'auth_test.test.validuser'};
my $validpassword=$testConfig{'auth_test.test.validpassword'};
my $validtoken1=$testConfig{'auth_test.test.validtoken1'};
my $validtoken2=$testConfig{'auth_test.test.validtoken2'};
my $invalidtoken=$testConfig{'auth_test.test.invalidtoken'};


note("Using auth server $authurl for testing");

my $at;
ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl), "Creating empty token");
ok( (not defined($at->error_message())), "Making sure empty token doesn't generate error");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'user_id' => $validuser,
    'password' => $testConfig{'auth_test.test.validpassword'}
    ), "Logging in using valid id and password");
ok($at->validate(), "Validating token using valid username/password");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authBadUrl,
    'user_id' => $validuser,
    'password' => $testConfig{'auth_test.test.validpassword'}
    ), "Logging in to bad auth server using valid id and password");
ok(!($at->validate()), "Testing that validating token using valid username/password and invalid auth service fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'user_id' => $testConfig{'auth_test.test.validuser'},
    'password' => $testConfig{'auth_test.test.invalidpassword'}
    ), "Logging in using valid account and bad password");
ok(!($at->validate()), "Testing that bad password fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'user_id' => $testConfig{'auth_test.test.invaliduser'},
    'password' => $testConfig{'auth_test.test.invalidpassword'}
    ), "Logging in using bad account and bad password");
ok(!($at->validate()), "Testing that bad userid/password fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl, 'user_id' => undef, ), "Logging in using undef user_id");
ok(!($at->validate()), "Testing that undef user_id fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => $validtoken1,
    ), "Logging in using valid token1");
ok($at->validate(), "Validating valid token1");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => $validtoken2,
    ), "Logging in using valid token2");
ok($at->validate(), "Validating valid token2");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => $invalidtoken,
    ), "Logging in using invalid token");
ok(!($at->validate()), "Testing that bad token fails");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl,
    'token' => '',
    ), "Logging in using empty token");
ok(!($at->validate()), "Testing that empty token fails");

#ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'password' => '@Suite525'), "Logging in using kbasetest account using username/password");
#ok($at->validate(), "Validating token from kbasetest username/password");

my $badtoken = <<EOT2;
un=papa|clientid=papa|expiry=2376607863|SigningSubject=https://graph.not.api.test.globuscs.info/goauth/keys/861eb8e0-e634-11e1-ac2c-1231381a5994|sig=321ca03d17d984b70822e7414f20a73709f87ba4ed427ad7f41671dc58eae15911322a71787bdaece3885187da1158daf37f21eadd10ea2e75274ca0d8e3fc1f70ca7588078c2a4a96d1340f5ac26ccea89b406399486ba592be9f1d8ffe6273b7acdba8a0edf4154cb3da6caa6522f363d2f6f4d04e080d682e15b35f0bbc36
EOT2

#ok( $at = Bio::KBase::AuthToken->new('token' => $badtoken), "Creating token with bad SigningSubject");
#ok(!($at->validate()), "Validating that bad SigningSubject fails");
#ok(($at->error_message() =~ /Token signed by unrecognized source/), "Checking for 'unrecognized source' error message");

note( "Creating settings for testing kbase_config");
Bio::KBase::Auth::SetConfigs('authpath'=>$authurl,"password" =>$validpassword,"user_id" => $validuser);

ok( $at = Bio::KBase::AuthToken->new(), "Creating a new token object for testing kbase_config with password");
ok( $at->user_id() eq $validuser, "Verifying that valid user was read from kbase_config");
ok( $at->validate(), "Verifying that valid user token was acquired properly with userid and password");

ok( $at = Bio::KBase::AuthToken->new('auth_svc'=>$authurl, ignore_kbase_config => 1), "Creating a blank object by ignoring the kbase_config file");
ok( ! defined($at->user_id()), "Verifying that kbase_config was ignored");

if ( -e $Bio::KBase::Auth::ConfPath) {
    # restore old config
    Bio::KBase::Auth::SetConfigs( %old_config);
}


done_testing();


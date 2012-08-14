#!/usr/bin/env perl
#
# Test the Authentication Token code
#
# sychan@lbl.gov
# 8/13/2012

use lib "../lib/";
use lib "lib";
use Data::Dumper;
use HTTP::Daemon;
use HTTP::Request;
use LWP::UserAgent;
use Net::OAuth;
use JSON;
use Digest::MD5 qw( md5_base64);
use Test::More 'no_plan';
use Storable qw(dclone);
use Test::Deep::NoTest qw(eq_deeply);
use Data::Dumper;


BEGIN {
    use_ok( Bio::KBase::AuthToken);
}

my @users = ();

sub testServer {
    my $d = shift;
    my $res = new HTTP::Response;
    my $msg = new HTTP::Message;
    my $at = new Bio::KBase::AuthToken;

    while (my $c = $d->accept()) {
	while (my $r = $c->get_request) {
	    note( sprintf "Server: Recieved a connection: %s %s\n\t%s\n", $r->method, $r->url->path, $r->content);

	    my $body = sprintf("You sent a %s for %s.\n\n",$r->method(), $r->url->path);
	    my $token = $r->header('Authorization');
	    $at->token( $token);
	    note( "Server received request with token: ".$token);
	    note( sprintf("Validation result on server side: %s", $at->validate()));
	    if ($at->validate()) {
		$res->code(200);
		$body .= sprintf( "Successfully logged in as user %s\n",
				  $at->user_id);
	    } else {
		$res->code(401);
		$body .= sprintf("You failed to login: %s.\n", $at->error_message);
	    }
	    $res->content( $body);
	    $c->send_response($res);
	}
	$c->close;
	undef($c);
    }
}

sub testClient {
    my $server = shift;

    my $ua = LWP::UserAgent->new();
    my $req = HTTP::Request->new( GET => $server. "someurl" );
    ###
    # AuthToken->new Test
    ###

    ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'password' => '@Suite525'), "Logging in using papa account using username/password");
    ok($at->validate(), "Valid client token for user kbasetest");
    $req->header("Authorization" => $at->token);

    ok( $res = $ua->request( $req), "Submitting authenticated request to server");
    ok( ($res->code >= 200) && ($res->code < 300), "Querying server with token in Authorization header");
    note( sprintf "Client: Recieved a response: %d %s\n", $res->code, $res->content);

    # As a sanity check, trash the oauth_secret and make sure that
    # we get a negative result
    $req->header("Authorization" => "bogo token");

    note( sprintf "Client: Sending bad request: %s %s (expecting failure)\n",$req->method,$req->url->as_string);
    $res = $ua->request( $req);
    ok( ($res->code < 200) || ($res->code >= 300), "Querying server with bad oauth creds, expected 401 error");
    note( sprintf "Client: Recieved a response: %d %s\n", $res->code, $res->content);

    # move back original .kbase-auth file
    if ( -e "~/.kbase-auth.testing") {
      `mv ~/.kbase-auth.testing ~/.kbase-auth`;
    }
}

# if logged in, logout
sub cond_logout(){
    my $ac = shift;

    if ($ac->{logged_in}){
         $ac->logout();
    }
}

ok( $at = Bio::KBase::AuthToken->new('user_id' => 'papa', 'password' => 'papa'), "Logging in using papa account");
ok($at->validate(), "Validating token for papa user using username/password");

ok( $at = Bio::KBase::AuthToken->new('user_id' => 'papa', 'password' => 'poopa'), "Logging in using papa account and bad password");
ok(!($at->validate()), "Testing that bad password fails");

ok( $at = Bio::KBase::AuthToken->new('user_id' => 'papa_blah', 'password' => ''), "Logging in using bad account and bad password");
ok(!($at->validate()), "Testing that bad account/password fails");

ok( $at = Bio::KBase::AuthToken->new('user_id' => undef, ), "Logging in using undef user_id");
ok(!($at->validate()), "Testing that undef user_id fails");

ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'password' => '@Suite525'), "Logging in using papa account using username/password");
ok($at->validate(), "Validating token from kbasetest username/password");

# Read in the RSA key from a local file
$rsakey = <<EOT;
-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC1QVwNCLinZJfKBfFaQm2nZQM0JvwVhV5fwjiLkUPF51I2HfEX
h988fOc2aOWuhPxUYOnE6I5xqMeWVh5T/77tOLs14X7O6kkmQZhsURKeIv9TVwNM
KoHyBRoE70p+K1qAA7szhz4DE+L0OuNa7H6oFVmpoOPq5GBwFqnFZZwqTwIBIwKB
gENSyms9wO23phfWUlS5lnFgCIEVy1hzXZFII6GNuhZOmuDmjL+Y3eNEVeECY/Bd
R8eRteoNPDjYSiHlePqg0eJ1CclHYOTR/ngBmqNxh5fSgscSPHIuoKlEVRrQE2BY
xM+BxMV4Kz7cZ3YKHrgMvHeNBL1eAhlO9iH4ur6i/UlDAkEA2loWVhabzQ2m3DYN
6m7W5NLuBIqRyvNh/zX8gETqwDWynLri4AAcBcerDPghnXkJDqlM7AgG8W1z05A1
VLhjpQJBANSB2kFjVOfdKJwkfvnn82nf/peHODDKUiaIwD7RaKOJFOI9ULJ6s/fJ
qOtJv/Gnv563Sy3p7pSDtH4PGKjXY+MCQBK3Q748c8EebWNVFyK5Cxrtgh2lejX3
mq95p+28w6oTOzIBY+dQd241r5Nlub0KX9yvbP5J1LWbqteepXxKUa8CQHNcbyrP
hdz0ZoCmGQtSB8vCvWgzdkZfM+kIaFydkJNKamwv6fp9H95I5qudEG09zmwaXAL7
VaEUTAnq8CEkeA0CQQCC4JLKFblHiZdEFzn6jkYe4s9Nf6SX7A+Vn4hq1o9yVMzf
+fEfmgafrDgETuDY9fbv8DwfGtIgaWsbXbvXKdFd
-----END RSA PRIVATE KEY-----
EOT

ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'client_secret' => $rsakey), "Logging in using kbasetest account using username/rsa_key");
ok($at->validate(), "Validating token for kbasetest username and rsakey");

ok( $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest', 'client_secret' => 'made2fail'), "Logging in using kbasetest account using bad rsa_key");
ok(!($at->validate()), "Validating failed RSA kbasetest login");


ok( $d = HTTP::Daemon->new( LocalAddr => '127.0.0.1'), "Creating a HTTP::Daemon object for handling AuthServer") || die "Could not create HTTP::Daemon";

note("Server listening at ".$d->url);

my $child = fork();
if ($child) {
    note( "Running client in parent process $$");
    testClient( $d->url);
} else {
    note( "Running server in pid $$");
    testServer( $d);
}

kill 9, $child;

done_testing();


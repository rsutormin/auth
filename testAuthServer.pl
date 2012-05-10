#!/bin/env perl
#
# Test some basic auth calls
# sychan@lbl.gov
# 5/3/12
#

use lib "libs/";
use Data::Dumper;
use Bio::KBase::AuthDirectory;
use Bio::KBase::AuthServer;
use Bio::KBase::AuthClient;
use HTTP::Daemon;
use HTTP::Request;
use LWP::UserAgent;
use Net::OAuth;

sub testServer {
    $d = shift;
    my $res = new HTTP::Response;
    my $msg = new HTTP::Message;
    my $as = new Bio::KBase::AuthServer;

    my $c = $d->accept();
    my $r = $c->get_request;
    print "Recieved a connection\n".Dumper($r);

    if ($r->method eq 'GET') {
	my $body = sprintf("You sent a %s for %s.\n",$r->method(), $r->url->path);
	$as->validate_request( $r);
	if ($as->valid) {
	    $body .= sprintf( "Successfully logged in as user %s\n",
			      $as->user->user_id);
	} else {
	    $body .= sprintf("You failed to login: %s.\n", $as->error_msg);
	}
	$res->content( $body);
	$c->send_response($res);
    } else {
	$c->send_error(RC_FORBIDDEN)
    }
    $c->close;
    undef($c);
}

sub testClient {
    my $server = shift;

    my $ua = LWP::UserAgent->new();
    my $req = HTTP::Request->new( GET => $server );

    # Create a KBase client and attach the authorization headers to the
    # request object. Use a canned key and secret that are in the test db
    my $ac = Bio::KBase::AuthClient->new(consumer_key => 'key3', consumer_secret => 'secret3');
    unless ($ac->{logged_in}) {
	die "Failed to login with credentials!";
    }
    unless ($ac->sign_request( $req)) {
	die "Failed to sign request";
    }
    print "Sending a request:\n".Dumper( $req);
    my $res = $ua->request( $req);
    print "Recieved a response:\n";
    print Dumper( $res);

}


my $d = HTTP::Daemon->new( LocalAddr => '127.0.0.1') || die "Could not create HTTP::Daemon";

print "Server listening at ".$d->url."\n";

my $pid = fork();
if ($pid) {
    print "Running client in pid $$\n";
    testClient( $d->url);
} else {
    print "Running server in pid $pid\n";
    testServer( $d);
}


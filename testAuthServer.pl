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

    my $c = $d->accept();
    my $r = $c->get_request;
    print "Recieved a connection\n".Dumper($r);
    if ($r->method eq 'GET') {
	$res->content( sprintf("Your sent a %s for %s",
			       $r->method(), $r->url->path));
	# remember, this is *not* recommended practice :-)
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
    my $res = $ua->request( $req);
    print "Recieved a response:\n";
    print Dumper( $res);

}


my $d = HTTP::Daemon->new( LocalAddr => '127.0.0.1') || die "Could not create HTTP::Daemon";

print "Server listening at ".$d->url."\n";

my $pid = fork();
if ($pid) {
    print "Running server in pid $pid\n";
    testServer( $d);
} else {
    print "Runnign client in pid $$\n";
    testClient( $d->url);
}

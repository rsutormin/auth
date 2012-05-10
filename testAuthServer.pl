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
use JSON;
use Digest::MD5 qw( md5_base64);

sub testServer {
    $d = shift;
    my $res = new HTTP::Response;
    my $msg = new HTTP::Message;
    my $as = new Bio::KBase::AuthServer;

    while (my $c = $d->accept()) {
	while (my $r = $c->get_request) {
	    printf "Server: Recieved a connection: %s %s\n\t%s\n", $r->method, $r->url->path, $r->content;
	    
	    my $body = sprintf("You sent a %s for %s.\n\n",$r->method(), $r->url->path);
	    $as->validate_request( $r);
	    if ($as->valid) {
		$body .= sprintf( "Successfully logged in as user %s\n",
				  $as->user->user_id);
	    } else {
		$body .= sprintf("You failed to login: %s.\n", $as->error_msg);
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

    # Create a KBase client and attach the authorization headers to the
    # request object. Use a canned key and secret that are in the test db
    my $ac = Bio::KBase::AuthClient->new(consumer_key => 'key3', consumer_secret => 'secret3');
    unless ($ac->{logged_in}) {
	die "Client: Failed to login with credentials!";
    }
    unless ($ac->sign_request( $req)) {
	die "Client: Failed to sign request";
    }
    printf "Client: Sending legit request: %s %s (expecting success)\n",$req->method,$req->url->as_string;
    my $res = $ua->request( $req);
    printf "Client: Recieved a response: %s\n", $res->content;

    # As a sanity check, trash the oauth_secret and make sure that
    # we get a negative result
    $secret = $ac->{oauth_cred}->{oauth_secret};
    $ac->{oauth_cred}->{oauth_secret} = 'blahbldhblsdhj';
    unless ($ac->sign_request( $req)) {
	die "Client: Failed to sign request";
    }
    printf "Client: Sending bad request: %s %s (expecting failure)\n",$req->method,$req->url->as_string;
    my $res = $ua->request( $req);
    printf "Client: Recieved a response: %s\n", $res->content;

    # restore the secret and send an example of a good request with an embedded JSON
    # string that includes an extra signature
    $ac->{oauth_cred}->{oauth_secret} = $secret;
    
    $req = HTTP::Request->new( POST => $server. "some_rpc_handler" );

    # The arguments to the method call
    #
    my @args = ("arg1", "arg2");

    #
    # For authenticated services, we wrap the parameters
    # in this hash where we pass the authorization token along
    # with the actual argument list. This is what I refer to
    # as the message envelope.
    #
    my $wrapped_params = {
	args => \@args,
    };

    #
    # The JSONRPC protocol data.
    #
    my $jsonrpc_params = {
	method => "module.server_call",
	params => [$wrapped_params],
    };

    my $json_call = to_json( $jsonrpc_params);
    my $param_hash = md5_base64( $json_call);

    # Use the oauth libraries to create an oauth token using "jsonrpc" as
    # the method, and a digest hash of rpc call parameters as the 'url'
    # this construction isn't recognized anywhere outside of KBase
    my $token = $ac->auth_token( request_method => 'jsonrpc',
				 request_url => $param_hash );
    my $wrapped = { params => [$json_call, $token],
		    version => 1.1,
		    method => "module.method_name" };

    $req->content( to_json( $wrapped));

    # Sign the http request for oauth
    unless ($ac->sign_request( $req)) {
	die "Client: Failed to sign request";
    }
    printf "Sending json-rpc request with embedded oauth token: %s %s\n\t%s\n",$req->method,$req->url->as_string,$req->content;
    my $res = $ua->request( $req);
    printf "Client: Recieved a response: %s\n", $res->content;
    
}


my $d = HTTP::Daemon->new( LocalAddr => '127.0.0.1') || die "Could not create HTTP::Daemon";

print "Server listening at ".$d->url."\n";

my $child = fork();
if ($child) {
    print "Running server in pid $child\n";
    testServer( $d);
} else {
    print "Running client in parent process\n";
    testClient( $d->url);
}

kill 9, $child;

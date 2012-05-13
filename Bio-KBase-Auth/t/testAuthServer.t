#!/bin/env perl
#
# Test some basic auth calls
# sychan@lbl.gov
# 5/3/12
#

use lib "../lib/";
use Data::Dumper;
use HTTP::Daemon;
use HTTP::Request;
use LWP::UserAgent;
use Net::OAuth;
use JSON;
use Digest::MD5 qw( md5_base64);
use Test::More tests => 9;

BEGIN {
    use_ok( Bio::KBase::AuthDirectory);
    use_ok( Bio::KBase::AuthServer);
    use_ok( Bio::KBase::AuthClient);
}

sub testServer {
    my $d = shift;
    my $res = new HTTP::Response;
    my $msg = new HTTP::Message;
    my $as = new Bio::KBase::AuthServer;

    while (my $c = $d->accept()) {
	while (my $r = $c->get_request) {
	    note( sprintf "Server: Recieved a connection: %s %s\n\t%s\n", $r->method, $r->url->path, $r->content);
	    
	    my $body = sprintf("You sent a %s for %s.\n\n",$r->method(), $r->url->path);
	    $as->validate_request( $r);
	    if ($as->valid) {
		$res->code(200);
		$body .= sprintf( "Successfully logged in as user %s\n",
				  $as->user->user_id);
	    } else {
		$res->code(401);
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
    ok( $ac = Bio::KBase::AuthClient->new(consumer_key => 'key3', consumer_secret => 'secret3'), "Logging in either consumer key and secret");
    unless ($ac->{logged_in}) {
	die "Client: Failed to login with credentials!";
    }
    unless (ok($ac->sign_request( $req), "Signing HTTP request")) {
	die "Client: Failed to sign request";
    }
    note( sprintf "Client: Sending legit request: %s %s (expecting success)\n",$req->method,$req->url->as_string);
    $res = $ua->request( $req);
    ok( ($res->code >= 200) && ($res->code < 300), "Querying server with oauth creds");
    note( sprintf "Client: Recieved a response: %d %s\n", $res->code, $res->content);

    # As a sanity check, trash the oauth_secret and make sure that
    # we get a negative result
    my $secret = $ac->{oauth_cred}->{oauth_secret};
    $ac->{oauth_cred}->{oauth_secret} = 'blahbldhblsdhj';
    unless ($ac->sign_request( $req)) {
	die "Client: Failed to sign request";
    }
    note( sprintf "Client: Sending bad request: %s %s (expecting failure)\n",$req->method,$req->url->as_string);
    $res = $ua->request( $req);
    ok( ($res->code < 200) || ($res->code >= 300), "Querying server with bad oauth creds, expected 401 error");
    note( sprintf "Client: Recieved a response: %d %s\n", $res->code, $res->content);

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
    # On the server side, to validate the request, you would extract
    # all the components and compute the md5_base64 hash of the
    # contents of $json_call, and then make a call like this
    # $as = Bio::KBase::AuthServer
    # $inf{request_method} = "jsonrpc";
    # $inf{request_url} = $param_hash
    # if ( $as->validate_auth_header( $token, %inf)) {
    #         good stuff
    # } else {
    #         bad stuff
    # }
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
    note( sprintf "Sending json-rpc request with embedded oauth token: %s %s\n\t%s\n",$req->method,$req->url->as_string,$req->content);
    my $res = $ua->request( $req);
    ok( ($res->code >= 200) && ($res->code < 300), "POST request with oauth cred in HTTP envelope and sample JSON-RPC message body");
    note( sprintf "Client: Recieved a response: %d %s\n", $res->code, $res->content);
    
}


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


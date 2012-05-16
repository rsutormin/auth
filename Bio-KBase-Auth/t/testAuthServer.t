#!/usr/bin/env perl
#
# Test some basic auth calls
# sychan@lbl.gov
# 5/3/12
#


#NOTE: json-rpc test prior line commented out, will always fail - was hanging script

use lib "../lib/";
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


BEGIN {
    use_ok( Bio::KBase::AuthDirectory);
    use_ok( Bio::KBase::AuthServer);
    use_ok( Bio::KBase::AuthClient);
}

my @users = ();

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

    ###
    # AuthClient->new Test
    ###

    # removing the effect of kbase-auth file
    if( -e "~/.kbase-auth") {
      `mv ~/.kbase-auth ~/.kbase-auth.testing`;
    }

    my $ac = '';
    # wrong key log-in test using new
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'kkkkkkkkkkkkkkkkkkkkkkkkkk', consumer_secret => 'secret3');
    ok($ac->{error_msg}, 'Wrong key should generate error message');
    is($ac->{logged_in}, 0, 'Wrong key should be failed to login');
    
    # wrong secret log-in test using new
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'key3', consumer_secret => 'ssssssssssssssssssssssssssssssssssssssssss');
    ok($ac->{error_msg}, 'Wrong secret should generate error message');
    is($ac->{logged_in}, 0, "Wrong secret should be failed to login");

    # empty user test
    $ac = Bio::KBase::AuthClient->new(); 
    is($ac->{error_msg}, '', "Create empty user instance without error");
    is($ac->{logged_in}, 0, "empty user shouldn't be logged in");


    # test using ~/.kbase-auth
    # wrong key log-in test using kbase-auth
    `echo " { \\"oauth_key\\":\\"kkkkkkkkkkkkkkkkkkkkkkkkkkkkk\\", \\"oauth_secret\\":\\"secret3\\" }" > ~/.kbase-auth;`;
    $ac = Bio::KBase::AuthClient->new(); 
    ok($ac->{error_msg}, 'Wrong key should generate error message using kbase-auth');
    is($ac->{logged_in}, 0, 'Wrong key should be failed to login using kbase-auth');

    # wrong secret log-in test using kbase-auth
    `echo " { \\"oauth_key\\":\\"key3\\", \\"oauth_secret\\":\\"ssssssssssssssssssssssssssssssssssssssssss\\" }" > ~/.kbase-auth;`;
    $ac = Bio::KBase::AuthClient->new(); 
    ok($ac->{error_msg}, 'Wrong secret should generate error message');
    is($ac->{logged_in}, 0, "Wrong secret should be failed to login");

    
    # correct key and secret log-in test using kbase-auth
    `echo " { \\"oauth_key\\":\\"key3\\", \\"oauth_secret\\":\\"secret3\\" }" > ~/.kbase-auth;`;
    $ac = Bio::KBase::AuthClient->new(); 
    is($ac->{error_msg}, '', "Correct key and secret should generate no error message");
    is($ac->{logged_in}, 1, "Correct key and secret should be able to login");

    # remove test .kbase-auth file 
    `rm ~/.kbase-auth`;

    # correct key and secret as parameter test
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'key3', consumer_secret => 'secret3'); 
    is($ac->{error_msg}, '', "Create user instance without error with correct key and secret");
    is($ac->{logged_in}, 1, "Correct key and secret should be logged in");
    
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'key3', consumer_secret => 'secret3', dummy_field => 'dummy_tokenkkkkkkkkkkkkkkkkkk'); 
    is($ac->{error_msg}, '', "Additional AuthClient->new parameter shouldn't cause error in terms of login");
    is($ac->{logged_in}, 1, "Additional AuthClient->new parameter shouldn't bother login");


    ###
    # logout/login tests from a black box perspective 5/15/12________
    ###
    
    #$user1 = createUser();
    
    #logout of original sesssion
    ok($ac->logout(), "Logout consumer_key = key3");
    
    #log back in w/ key
    ok($ac->login(consumer_key => 'key3', consumer_secret => 'secret3'), "Log back in w/ consumer_key = key3 and secret = secret3");
    
    cond_logout($ac); #conditional logout
    
    #login w/ fresh client connection
    ok($ac = Bio::KBase::AuthClient->new(consumer_key => 'key4', consumer_secret => 'secret4'), "Make new client connection w/ c_k = key4 and secret = secret4");
    
    #double logout - second should fail
    $ac->logout();
    ok(!$ac->logout(), "Double logout should return false");
    # should also add a check for the correct error message, but that's undocumented
    
    #check login as same user has same profile
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'key4', consumer_secret => 'secret4');
    $user4 = dclone($ac->user);
    $ac->logout();
    $ac->login(consumer_key => 'key4', consumer_secret => 'secret4');
    is_deeply($user4, $ac->user, "Test that multiple logins as the same user provides the same profile");
    
    cond_logout($ac);
    
    #check login as different user has different profile
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'key5', consumer_secret => 'secret5');
    $user5 = dclone($ac->user);
    $ac->logout();
    $ac->login(consumer_key => 'key4', consumer_secret => 'secret4');
    #no is_not_deeply, unfortunately
    ok(!eq_deeply($user5, $ac->user), "Test that multiple logins as the different users provide different profiles");
    
    cond_logout($ac);
    
    $ac = Bio::KBase::AuthClient->new(consumer_key => 'key5', consumer_secret => 'secret5');
    
    #More stuff to test
    #test async_return_url behavior for login and logout
    #test conversation_callback 
    
    #Other notes:
    # What happens if the current test @ 140.221.92.45 isn't available or the data has been changed? All tests will fail in the former and the the original tests will fail in the latter.
    
    
    redrumAll(); # remove all created users
    
    ##
    #__________original tests_____________
    ##
    
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
    # this construction isn't recognized anywhere outside of KBaperse
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
    #my $res = $ua->request( $req);
    ok( ($res->code >= 200) && ($res->code < 300), "POST request with oauth cred in HTTP envelope and sample JSON-RPC message body");
    note( sprintf "Client: Recieved a response: %d %s\n", $res->code, $res->content);


    # move back original .kbase-auth file
    if ( -e "~/.kbase-auth.testing") {
      `mv ~/.kbase-auth.testing ~/.kbase-auth`;
    }  
}

# if logged in, logout
sub cond_logout(){
    $ac = shift;
     
    if ($ac->{logged_in}){
         $ac->logout();
    }
}

sub createUser() {
     
     my $random_user_id = 'hackz0rz_oh_no_' . time . int(rand(100000000000));

     my $user = Bio::KBase::AuthUser->new(
          'email' => "something\@somewhere.com",
          'user_id' => $random_user_id,
          'name' => 'My pants are exquisite in their own way thank you',
     );
     #print Dumper($user); use Data::Dumper;
     $authdirectory = Bio::KBase::AuthDirectory->new();
     my $user = $authdirectory->create_user($user);
     
     push(@users, $user); #record users for deletion later
     
     note("Created test user " . $random_user_id);
     
     #print $authdirectory->error_message, "\n";
     return $user;
}

# delete one user
sub redrum(){
     $authdirectory = Bio::KBase::AuthDirectory->new();
     $user = shift;
     $ad->delete_user($user->user_id);
}

# delete all users
sub redrumAll(){
     
     my $ad = Bio::KBase::AuthDirectory->new();
     foreach my $u (@users) {
     note("Deleted test user " . $u->user_id);
        $ad->delete_user($u);
     }
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


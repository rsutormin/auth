package Bio::KBase::AuthClient;

use strict;
use warnings;
use Object::Tiny::RW qw { user logged_in error_message oauth_creds};
use Bio::KBase::Auth;
use Bio::KBase::AuthUser;
use MIME::Base64;
use Bio::KBase::AuthDirectory;
use JSON;
use Net::OAuth;
use Digest::MD5 qw(md5_base64);
use Digest::SHA1 qw(sha1_base64);
use Data::Dumper;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use URI;
use URI::QueryParam;
use POSIX;

# Location of the file where we're storing the authentication
# credentials
# It is a JSON formatted file with the following
# {"user_id":"username",
#  "password":"user password",
#  "client_id":"client_key_blahblah",
#  "client_secret":"client_secret_blahblah",
#  "auth_token":"client_blah_blah",
# }
#

our $auth_rc = "~/.kbase-auth";

sub new {
    my $class = shift @_;
    my %params = @_;

    my $self = $class->SUPER::new(
        'user'       => Bio::KBase::AuthUser->new,
        'oauth_creds' => {},
        'logged_in'  => 0,
        'error_message'  => "",
        @_
    );

    # Try calling login to see if creds defined

    eval {

	my @x = glob( $auth_rc);
	my $auth_rc = shift @x;
	my %creds;
	if (exists($params{ 'user_id'}) ||
	    exists($params{ 'auth_token'})) {
	    $self->login( %params);
	    unless ($self->{logged_in}) {
		die( "Authentication failed:" . $self->error_message);
	    }
	} elsif (%creds = read_authrc( $auth_rc)) {
	    unless ($self->login( %creds)) {
		# login failed, pass the error message along. Redundant for now, but
		# we don't want later code possibly stomping on this result
		die "auth_rc credentials failed login: " . $self->error_message;
	    }
	}
    };
    if ($@) {
	$self->error_message($@);
    }
    return $self;
}

# Login using Globus Online service. Check for proper set of
# credentials, authenticate using them to fetch an access token
# Fetch the user's profile object from the Globus profile
# service. 
sub login {
    my $self = shift;
    my %creds = @_;

    $self->{'logged_in'} = 0;
    # Check for credentials
    eval {
	my @x = glob( $auth_rc);
	my $auth_rc = shift @x;
        unless ( ($creds{'user_id'} && 
		  ($creds{'client_secret'} || $creds{'password'})) ||
		 ($creds{'client_id'} && $creds{'client_secret'}) ||
		 ($creds{'auth_token'})) {
	    my $creds = read_authrc( $auth_rc);
	    %creds = %$creds;
        }
    };
    if ($@) {
	$self->error_message("Invalid local credentials: $@");
    	return 0;
    }
    # If we have a token, skip this part where we try to get a token
    unless ($creds{'auth_token'}) {
	eval {
	    $creds{'auth_token'} = $self->get_nexus_token( %creds);
	};
	if ($@) {
	    $self->error_message("Globus rejected credentials: $@");
	    return(0);
	}
    }

    $self->{'oauth_creds'} = \%creds;
    # Use the token to fetch the user profile
    eval {
	$self->user->get( $self->{'oauth_creds'}->{'auth_token'});
    };
    if ($@) {
	$self->error_message("Could not fetch user profile using token: $@");
	return(0);
    }
    $self->{'user'}->{'oauth_creds'} = \%creds;
    return( $self->{logged_in} = 1);
}

sub sign_request {
    my $self = shift;
    my $request = shift;

    # setup the request method and URL

    # Create the appropriate authorization header with the auth_token
    # call and then push it into the request envelope
    my $authz_hdr = $self->auth_token( body => $request->content);

    $request->header( Authorization => $authz_hdr);

    return 1;
}

sub auth_token {
    my $self = shift;
    my %p = @_;

    unless ( defined( $self->{'oauth_creds'})) {
    	carp( "No oauth_creds defined in AuthClient object. Are you logged in?\n");
	    return;
    }

    return($self->get_nexus_token( body => $p{'body'}, %{$self->{'oauth_creds'}}));
}


sub new_consumer {
    my $self = shift @_;
    my %p = @_;

    unless (defined( $p{'alias'})) {
	$self->error_message("alias parameter not set");
	return( undef);
    }
    unless (defined( $p{'rsa_key'})) {
	$self->error_message("rsa_key parameter not set");
	return( undef);
    }
    unless ( $self->{logged_in}) {
	$self->error_message("No user currently logged in");
    	return( undef);
    }
    
}

sub logout {
    my $self = shift @_;
    
    if ( $self->{logged_in} ) {
	$self->{user} = Bio::KBase::AuthUser->new( user_id => "", password => "");
	$self->{logged_in} = 0;
	$self->{oauth_creds} = {};
	return(1);
    } else {
	$self->{error_message} = "Not logged in";
	return(0);
    }

}

# Reads the auth_rc file and check for legit set of credentials
# return if there is a legit set of credentials for login
# otherwise throw an exception. The caller should be prepared to catch the
# exception and just deal with no creds.
# Returns undef if the auth_rc file is non-existent, throws error if
# is unreadable
sub read_authrc {
    my $auth_rc = shift @_;
    my $creds;

    unless ( $auth_rc && -e $auth_rc) {
	return( undef );
    }

    if ( -r $auth_rc) {
	open RC, "<", $auth_rc;
	my @rc = <RC>;
	close RC;
	chomp( @rc);
	$creds = from_json( join( '',@rc));
    } else {
	die( "$auth_rc is unreadable");
    }

    # if we have an oauth_token, we're good and
    # can just return right away
    if ( defined( $creds->{'auth_token'})) {
	return( %$creds);
    }
    
    # otherwise check for necessary subsets of
    # info for login
    unless ( defined( $creds->{'user_id'}) ||
	     defined( $creds->{'client_id'})) {
	die "No user_id or client_id found";
    }

    if ( defined( $creds->{'client_secret'}) &&
	 (defined( $creds->{'user_id'}) ||
	  defined( $creds->{'client_id'}))) {
	return( %$creds);
    } elsif (defined( $creds->{'user_id'}) &&
	     defined( $creds->{'password'})) {
	return( %$creds);
    } else {
	die "Need either (user_id, (password || client_secret)) or (client_id, client_secret) to be defined.";
    }
}

# Get a nexus token, using either user_id, password or user_id, rsakey.
# Parameters passed in as a hash, looking for
# body => body of the http message, if any, can be undefined
# user_id => user name recognized on globus online for login
# client_id => user name recognized on globus online for login
# client_secret => the RSA private key used for signing
# password => Globus online password
# Throws an exception if either invalid set of creds or failed login

sub get_nexus_token {
    my $self = shift @_;
    my %p = @_;
    my $path = $Bio::KBase::Auth::AuthorizePath;
    my $url = $Bio::KBase::Auth::AuthSvcHost;
    my $method = "GET";
    my $headers;
    my $nexus_response;

    eval {
	# Make sure we have the right combo of creds
	if ($p{'user_id'} && ($p{'client_secret'} || $p{'password'})) {
	    # no op
	# client_id and client_secret do not seem to be supported currently by Globus
	#} elsif ( $p{'client_id'} && $p{'client_secret'}) {
	#    # no op
	} else {
	    die("Need either (user_id, client_secret || password) or (client_id, client_secret) to be defined.");
	}
	
	my $u = URI->new($url);
	my %qparams = ("response_type" => "code",
		       "client_id" => $p{'client_id'} ? $p{'client_id'} : $p{'user_id'});
	$u->query_form( %qparams );
	my $query=$u->query();
	
	# Okay, if we have user_id/password, get token using that, otherwise use the
	# user_id and client_secret for RSA authentication
	if ( $p{'user_id'} && $p{'password'}) {
	    $headers = HTTP::Headers->new;
	    $headers->authorization_basic( $p{'user_id'}, $p{'password'});
	} else {
	    my %p2 = ( rsakey => $p{'client_secret'},
		       path => $path,
		       method => $method,
		       user_id => $p{'user_id'},
		       query => $query,
		       body => $p{'body'} );
	    
	    my %headers = sign_with_rsa( %p2);
	    $headers = HTTP::Headers->new( %headers);
	}
	my $client = LWP::UserAgent->new(default_headers => $headers);
	# set a 5 second timeout
	$client->timeout(5);
	$client->ssl_opts(verify_hostname => 0);
	my $geturl = sprintf('%s%s?%s', $url,$path,$query);
	my $response = $client->get( $geturl);
	unless ($response->is_success) {
	    die $response->status_line;
	}
	$nexus_response = decode_json( $response->content());
	unless ($nexus_response->{'code'}) {
	    die "No token returned by Globus Online";
	}
    };
    if ($@) {
	die "Failed to get auth token: $@";
    } else {
	return($nexus_response->{'code'} );
    }
}

# The basic sha1_base64 does not properly pad the encoded text
# so we have this little wrapper to tack on extra '='.
sub sha1_base64_padded {
    my $in = shift;
    my @pad = ('','===','==','=');

    my $out = sha1_base64( $in);
    return ($out.$pad[length($out) % 4]);
}

# Return a hash of HTTP headers used by Globus Nexus to authenticate
# a token request.
sub sign_with_rsa {
    my %p = @_;

    # The sha1_base64 functions choke on an undefs, so
    # set body to an empty string if it is undef
    unless (defined($p{'body'})) {
	$p{'body'} = "";
    }
    my $timestamp = canonical_time(time());
    my %headers = ( 'X-Globus-UserId' => $p{user_id},
		    'X-Globus-Sign'   => 'version=1.0',
		    'X-Globus-Timestamp' => $timestamp,
	);
    
    my $to_sign = join("\n",
		       "Method:%s",
		       "Hashed Path:%s",
		       "X-Globus-Content-Hash:%s",
		       "X-Globus-Query-Hash:%s",
		       "X-Globus-Timestamp:%s",
		       "X-Globus-UserId:%s");
    $to_sign = sprintf( $to_sign,
			   $p{method},
			   sha1_base64_padded($p{path}),
			   sha1_base64_padded($p{body}),
			   sha1_base64_padded($p{query}),
			   $timestamp,
			   $headers{'X-Globus-UserId'});
    my $pkey = Crypt::OpenSSL::RSA->new_private_key($p{rsakey});
    $pkey->use_sha1_hash();
    my $sig = $pkey->sign($to_sign);
    my $sig_base64 = encode_base64( $sig);
    my @sig_base64 = split( '\n', $sig_base64);
    foreach my $x (0..$#sig_base64) {
	$headers{ sprintf( 'X-Globus-Authorization-%s', $x)} = $sig_base64[$x];
    }
    return(%headers);
    
}

# Formats a time string in the format desired by Globus Online
# It is somewhat bogus, because they are claiming that it is
# UTC, when in fact its the localtime.           
sub canonical_time {
    my $time = shift;
    return( strftime("%Y-%m-%dT%H:%M:%S", localtime($time)) . 'Z');

}


1;

__END__

=pod

=head1 Bio::KBase::AuthClient

   Client libraries that handle KBase authentication.

=head2 Examples:

=over

=item Conventional OAuth usage with Authorization header in http header:

    my $ua = LWP::UserAgent->new();
    my $req = HTTP::Request->new( GET => $server. "someurl" );

    # Create a KBase client and attach the authorization headers to the
    # request object. Use a "key" and "secret" as the secret, where secret
    # is an RSA private key where the public key has been associated with the
    # username on Globus nexus
    my $ac = Bio::KBase::AuthClient->new(user_id => 'username', client_secret => 'secret');
    unless ($ac->{logged_in}) {
        die "Client: Failed to login with credentials!";
    }
    unless ($ac->sign_request( $req)) {
        die "Client: Failed to sign request";
    }
    my $res = $ua->request( $req);
    print $res->content

=item Embedding a non-standard OAuth token within JSON-RPC message body:

    # The arguments to the method call
    #
    my @args = ("arg1", "arg2");

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
    my $json_call = to_json( $jsonrpc_params);
    my $param_hash = md5_base64( $json_call);

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
     my $res = $ua->request( $req);
    printf "Client: Recieved a response: %s\n", $res->content;

=back

=head2 Environment

   User home directories can contain $auth_rc, which is a JSON formatted file with declarations for authentication information (similar to a ~/.netrc file)
   It should be in the following format:

{ "oauth_key":"consumer_key_blahblah",
  "oauth_token":"token_blah_blah",
  "oauth_secret":"client_secret_blahblah"
 }

=head2 Instance Variables

=over

=item B<user> (Bio::KBase::AuthUser)

Contains information about the user using the client. Also the full set of oauth credentials available for this user

=item B<oauth_creds> (hash)

Contains the hashref to specific oauth credential used for authentication. It is a hash of the same structure as the oauth_creds entries in the Bio::KBase::AuthUser

=item B<logged_in> (boolean)

Did login() successfully return? If this is true then the entry in the user attribute is good.

=item B<error_message> (string)

Most recent error msg from call to instance method.

=back

=head2 Methods

=over

=item B<new>([consumer_key=>key, client_secret=>secret])

returns Bio::KBase::AuthClient

Class constructor. Create and return a new client authentication object. Optionally takes arguments that are used for a call to the login() method. By default will check ~/.kbase-auth file for declarations for the consumer_key and client_secret, and if found, will pull those in and perform a login(). Environment variables are also an option and should be discussed.

=item B<login>( [user_id => someuserid, consumer_key=>key, client_secret=>secret] |
[user_id=>”someuserid”,[password=>’somepassword’] |
[conversation_callback => ptr_conversation_function] |
[return_url = async_return_url])>

returns boolean for login success/fail.

If no parameters are given then consumer (key,secret) will be populated automatically from ~/.kbase-auth. Environment variables are also an option.

When this is called, the client will attempt to connect to the back end server to validate the credentials provided.
The most common use case will be to pull the consumer_key and client_secret from the environment. You can also specify the user_id and password for authentication - this is only recommended for bootstrapping the use of consumer (key,secret).

If the authentication is a little more complicated there are 2 options
  - define a function that handles the login interaction (same idea as the PAM conversation function).
  - if we’re in a web app that needs oauth authentication, then the client browser will need to be redirected back and forth. A return url where control will pass once authentication has completed needs to be provided ( see this diagram for an example). If the return_url is provided, this function will not return.


=item B<sign_request>( HTTPRequest request_object,[Bio::KBase::AuthUser user])

returns boolean

Called to sign a http request object before submitting it. Will push authentication/authorization messages into the HTTP request headers for authentication on the server side. With OAuth 1.0(a) this will be one set of headers, and with OAuth 2.0 it should be a smaller, simpler set of headers
   This method must be called on a request object to “sign” the request header so that the server side can authenticate the request.
   Note that different authentication methods have different requirements for a request:
   1) username/password requires SSL/TLS for obvious reasons
   2) oauth1 uses shared secrets and cryptographic hashes, so the request can be passed in the clear
   3) oauth2 using MAC tokens use a shared secret, so the request can be in cleartext
   4) oauth2 using Bearer tokens uses a text string as a combination username/password, so it must be over SSL/TLS
   If the transport protocol violates the requirements of the authentication method, sign_request() will return false and not encode any information in the request header.
   We can simplify things if we simply settle on options 2 and 3, and rule out options 1 and 4. It is also possible to finesse #1 into a cleartext protocol as well. But #4 (oauth2 bearer tokens) *must* be SSL/TLS. My recommendation is to disallow #4 so that we do not have to require SSL/TLS.

=item B<auth_token>( string URL,[Bio::KBase::AuthUser user]) **not yet implemented** (user consumer key/secret for now)

returns string

Returns a base64 encoded authentication token (tentatively based on the XOauth SASL token) that can be used for a single session within a non-HTTP protocol. The URL passed in is used to identify the resource being accessed, and is used in the computation of the hash signature. The url passed to Bio::KBase::AuthServer::validate_auth_token() on the other end of the exchange must be identical. Authentication tokens are also timestamped and intended for a single use. The token is generated from the consumer key and secret, and should not be stored across sessions for re-use (at the very least, it should timeout even if token replay safeguards fail).

=item B<new_consumer()> returns hash { consumer_key => key, client_secret => secret}

This function requests a consumer (key,secret) pair from the user directory that can be used for subsequent authentication. The (key,secret) should be stored in the environment. Note that the key/secret are associated with the account when you generate it - please do not overuse and cause a proliferation of key/secret pairs.

=item B<logout>([return_url = async_return_url])

returns boolean

Wipe out the auth info, and perform related logout functions. If we are being called in a web app, provide an asynchronous call back URL that the client browser will be redirected to after logout is called - execution will not return if return_url is defined.


=back

=cut

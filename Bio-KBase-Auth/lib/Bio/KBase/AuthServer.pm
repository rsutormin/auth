package Bio::KBase::AuthServer;

use strict;
# We use Object::Tiny::RW to generate getters/setters for the attributes
# and save ourselves some tedium
use Object::Tiny::RW qw {
    user
    valid
    auth_protocol
    error_msg
};
use Bio::KBase::AuthDirectory;
use Bio::KBase::AuthUser;
use Bio::KBase::Auth;
use HTTP::Request;
use Net::OAuth::Response;
use URI::Escape;
use Carp;
use Data::Dumper;

# set OAuth 1.0a for now
$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;


my $rest = undef;

sub decode {
    my $str = shift;
    return uri_unescape($str);
}

sub new() {
    my $class = shift;
    my $self = { 'user' => {},
		 'valid' => 1,
		 'auth_protocol' => 'oauth',
		 'error_msg' => '',
    };
    eval {
	unless ( defined($rest)) {
	    $rest = new REST::Client( host => $Bio::KBase::Auth::AuthSvcHost);
	}
    };
    if ($@) {
	# handle exception
	return( undef);
    } else {
	bless $self, $class;
	return($self);
    }

}

sub normalized_request_url {
    my $self = shift;
    my $req = shift;
    
    my ($proto) = $req->protocol =~ /([a-zA-Z]+)/;
    $proto = lc( $proto);
    my $host = $req->headers->{host};
    my $path = $req->uri->path;
    if (( $proto eq "https") && ($host =~ /:443$/)) {
	$host =~ s/:443$//;
    } elsif (( $proto eq "http") && ($host =~ /:80$/)) {
	$host =~ s/:80$//;
    }
    return( sprintf( '%s://%s%s', $proto, $host, $path));
    
}

sub validate_request() {
    my $self=shift @_;
    my $request = shift;

    unless ('HTTP::Request' eq ref $request) {
	carp "Require a request object";
	return 0;
    }
    my $AuthzHeader = $request->header('Authorization');
    unless ($AuthzHeader) {
	carp "HTTP Request lacks Authorization header";
	return 0;
    }

    # Gather params necessary to validate the request
    my %AuthInf = {};
    $AuthInf{'request_method'} = $request->method;
    $AuthInf{'request_url'} = $self->normalized_request_url($request);

    # Pass this header into the validate_auth_header function
    return( $self->validate_auth_header( $AuthzHeader, %AuthInf));
}


sub validate_auth_header() {
    my $self=shift @_;
    my $AuthzHeader = shift @_;
    my %AuthInf = @_;

    unless ( $AuthzHeader) {
	carp "Authorization Header not passed in";
	return 0;
    }

    unless ( %AuthInf) {
	carp "Authorization information not passed in";
	return 0;
    }

    # Parse out the header so that we can lookup the consumer secret, etc...
    # code cribbed from NET::OAuth::Message
    my $Authz2 = $AuthzHeader;
    croak "Header must start with \"OAuth \"" unless $Authz2 =~ s/OAuth //;
    my @pairs = split /[\s]*,[\s]*/, $Authz2;
    my %params;
    my $pair;
    my $user;
    foreach $pair (@pairs) {
        my ($k,$v) = split /=/, $pair;
        if (defined $k and defined $v) {
            $v =~ s/(^"|"$)//g;
	    ($k,$v) = map decode($_), $k, $v;
	    $params{$k} = $v;
	}
    }
    # Lookup user record based on the consumer key
    unless ($params{'oauth_consumer_key'}) {
	carp "Consumer key not found among authorization parameters";
	return 0;
    }
    
    my $AuthDir = new Bio::KBase::AuthDirectory;
    unless ( $user = $AuthDir->lookup_consumer( $params{'oauth_consumer_key'})) {
	carp "Consumer key was not found in database";
	return 0;
    }
    $AuthInf{'consumer_secret'} = $user->{'oauth_creds'}->{$params{'oauth_consumer_key'}}->{'oauth_secret'};
    unless ( $AuthInf{'consumer_secret'}) {
	carp "Internal error, failed to lookup consumer secret";
	return 0;
    }

    my $OAuthRequest = Net::OAuth->request('consumer')->from_authorization_header($AuthzHeader, %AuthInf);

    $self->{'valid'} = $OAuthRequest->verify();
    if ( $self->{'valid'}) {
	$self->{'user'} = $user;
	$self->{'auth_protocol'} = 'oauth1';
	$self->{'error_msg'} = ''
    } else {
	$self->{'error_msg'} = "Failed signature validation";
    }
    return( $self->{'valid'});
}

1;

__END__

=pod

=head1 Bio::KBase::AuthServer

Server side API for protecting a KBase resource.

=head2 Examples

    my $d = new HTTP::Daemon;
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


=head2 Instance Variables

=over

=item B<user> (Bio::KBase::AuthUser)

Contains current user provided by client

=item B<valid> (boolean)

Did the user’s credentials validate?

=item B<auth_protocol> (string)

Protocol used for authentication (oauth1,oauth2,user/password, etc...)

=item B<error_msg> (string)

Any errors generated during validation

=back

=head2 Methods

=over

=item B<new([request_object])>

returns Bio::KBase::AuthServer 

   Object constructor. Optionally takes an HTTP request object that will be handed to validate_request() for authentication information. If the request object has legitimate auth information the User and user_id attributes  will be populated, if not then the userid attribute will be null/undef.

=item B<validate_request( request_object)>

returns boolean

    Performs the real work of validating a request.
Examines the HTTP request headers for credentials
and then validate the credentials using OAuth crypto protocols.
Query the user database/registry for user profile information.
Populate the user attribute with user profile information
   Returns true if the request is properly authenticated and fills in the authenticated user

=item B<validate_auth_token( string URL, string auth_header)>

returns boolean

    Performs validation of the authentication token (string containing OAuth attributes)
Validate the credentials, making sure that the URL embedded in the authentication tokeno matches the URL passed into the function
Query the user database/registry for user profile information.
Populate the user attributes with user profile information
   Returns true if the header string properly authenticates and fills in the authenticated user

=back

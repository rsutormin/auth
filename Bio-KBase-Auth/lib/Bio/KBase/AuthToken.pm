package Bio::KBase::AuthToken;

use strict;
use warnings;
use JSON;
use Bio::KBase::Auth;
use LWP::UserAgent;

# We use Object::Tiny::RW to generate getters/setters for the attributes
# and save ourselves some tedium
use Object::Tiny::RW qw {
    token
    error_message
};


sub new() {
    my $class = shift;

    # Don't bother with calling the Object::Tiny::RW constructor,
    # since it doesn't do anything except return a blessed empty hash
    my $self = $class->SUPER::new(
        'token' => undef,
        'error_message' => undef,
        @_
    );

    return($self);
}

sub user_id {
    my $self = shift;

    return();
}

# function that handles Globus Online requests
# takes the following params in hash
# path => path/query part of the URL, doesn't include protocol/host
# token => token string to be used, if not provided will
#         look for oauth_creds->oauth_token. Value will go
#         into X-GLOBUS-GOAUTHTOKEN header
# method => (GET|PUT|POST|DELETE) defaults to GET
# body => string for http content
#         Content-Type will be set to application/json
#         automatically
# headers => hashref for any additional headers to be put into
#         the request. X-GLOBUS-GOAUTHTOKEN automatically set
#         by token param
#
# Returns a hashref to the json data that was returned
# throw an exception if there is an error, make sure you
# trap this with an eval{}!
sub go_request {
    my $self = shift @_;
    my %p = @_;

    my $json;
    eval {
	my $baseurl = $Bio::KBase::Auth::AuthSvcHost;
	my %headers;
	unless ($p{'token'}) {
	        $p{'token'} = $self->oauth_creds->{'auth_token'};
	}
	unless ($p{'token'}) {
	    die "No authentication token";
	}
	unless ($p{'path'}) {
	    die "No path specified";
	}
	$headers{'X-GLOBUS-GOAUTHTOKEN'} = $p{'token'};
	$headers{'Content-Type'} = 'application/json';
	if (defined($p{'headers'})) {
	    %headers = (%headers, %{$p{'headers'}});
	}
	my $headers = HTTP::Headers->new( %headers);
    
	my $client = LWP::UserAgent->new(default_headers => $headers);
	$client->timeout(5);
	$client->ssl_opts(verify_hostname => 0);
	my $method = $p{'method'} ? $p{'method'} : "GET";
	my $url = sprintf('%s%s', $baseurl,$p{'path'});
	my $req = HTTP::Request->new($method, $url);
	if ($p{'body'}) {
	    $req->content( $p{'body'});
	}
	my $response = $client->request( $req);
	unless ($response->is_success) {
	    die $response->status_line;
	}
	$json = decode_json( $response->content());
	$json = $self->_SquashJSONBool( $json);
    };
    if ($@) {
	die "Failed to query Globus Online: $@";
    } else {
	return( $json);
    }

}

sub _SquashJSONBool {
    # Walk an object ref returned by from_json() and squash references
    # to JSON::XS::Boolean into a simple 0 or 1
    my $self = shift;
    my $json_ref = shift;
    my $type;

    foreach (keys %$json_ref) {
	$type = ref $json_ref->{$_};
	next unless ($type);
	if ( 'HASH' eq $type) {
	    _SquashJSONBool( $self, $json_ref->{$_});
	} elsif ( 'JSON::XS::Boolean' eq $type) {
	    $json_ref->{$_} = ( $json_ref->{$_} ? 1 : 0 );
	}
    }
    return $json_ref;
}


1;

__END__

=pod

=head1 Bio::KBase::AuthUser

User object for KBase authentication. Stores user profile and authentication information, including oauth credentials.

This is a container for user attributes - creating, destroying them in the user database is handled by the Bio::KBase::AuthDirectory class.

=head2 Examples

   my $user = Bio::KBase::AuthUser->new()
   # Voila!

=head2 Instance Variables

=over


=item B<user_id> (string)

REQUIRED Identifier for the End-User at the Issuer.

=item B<error_message> (string)

contains error messages, if any, from most recent method call

=item B<enabled> (boolean)

Is this user allowed to login

=item B<last_login_time> (timestamp)

time of last login

=item B<last_login_ip> (ip address)

ip address of last login

=item B<roles> (string array)

An array of strings for storing roles that the user possesses

=item B<groups> (string array)

An array of strings for storing Unix style groups that the user is a member of

=item B<oauth_creds> (hash)

reference to hash array keyed on consumer_keys that stores public keys, private keys, verifiers and tokens associated with this user

=item B<name> (string)

End-User's full name in displayable form including all name parts, ordered according to End-User's locale and preferences.

=item B<email> (string)

The End-User's preferred e-mail address.

=item B<verified> (boolean)

True if the End-User's e-mail address has been verified; otherwise false.

=item B<updated_time> (string)

Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.

=back

=head2 Methods

=over

=item B<new>()

returns a Bio::KBase::AuthUser reference

=back

=cut

package Bio::KBase::AuthUser;

use strict;
use warnings;
use JSON;
use REST::Client;
use Bio::KBase::Auth;

# We use Object::Tiny::RW to generate getters/setters for the attributes
# and save ourselves some tedium
use Object::Tiny::RW qw {
    token
    error_message
    enabled
    last_login_time
    last_login_ip
    roles
    groups
    oauth_creds
    name
    email
    verified
    updated_time
};

our @top_attrs = ("username", "email_validated", "opt_in", "fullname", "email","system_admin");
our $rest;

sub new() {
    my $class = shift;

    # Don't bother with calling the Object::Tiny::RW constructor,
    # since it doesn't do anything except return a blessed empty hash
    my $self = $class->SUPER::new(
        'oauth_creds' => {},
        @_
    );

    unless ( defined $rest) {
        $rest = new REST::Client( host => $Bio::KBase::Auth::AuthSvcHost);
    }

    return($self);
}

sub user_id {
    my $self = shift;
    my $user_id = shift;

    # If there is a user_id value set already, do not accept a new
    # value, just return the old value

    if ($user_id && !(exists $self->{user_id})) {
	$self->{'user_id'} = $user_id;
    }
    return( $self->{'user_id'});
}

# This function updates the current user record. We must be
# logged in, and the parameters are a hash of the name/values
# that are to be updated.
# Attributes that aren't part of the @top_attrs list defined
# at the top of this module are pushed into the custom_fields
# hash.
# A special hash key called "__subpath__" can be defined to
# have it added to the URL path, for updating a subpath, like
# credentials/ssh
sub update {
    my $self = shift;
    my %p = @_;
    my $json;
    my $token = $self->oauth_creds->{'auth_token'};

    my $path = $Bio::KBase::Auth::ProfilePath;
    my $url = $Bio::KBase::Auth::AuthSvcHost;
    my %headers;
    my ($user_id) = $token =~ /un=(\w+)/;

    eval {
	unless ($token) {
	    die "Not logged in.";
	}
	unless (keys( %p)) {
	    die "No values for update";
	}
	$path .= "/".$self->{'user_id'};
	if (defined( $p{'__subpath__'})) {
	    $path .= "/".$p{'__subpath__'};
	}
	# strip out any hash keys that begin with "_"
	my %attrs = map { $_, $p{$_}} grep { ! /^_/ } (keys %p);
	# construct top level hash for appropriate attrs
	my %top;
	foreach my $x (@top_attrs) {
	    if (exists($attrs{ $x})) {
		$top{$x} = $attrs{$x};
		delete( $attrs{$x});
	    }
	}
	# any leftovers go into custom_fields
	if (keys %attrs) {
	    $top{'custom_fields'} = \%attrs;
	}
	
	$json = to_json( \%top);

	$headers{'X-GLOBUS-GOAUTHTOKEN'} = $token;
	$headers{'Content-Type'} = 'application/json';
	my $headers = HTTP::Headers->new( %headers);
    
	my $client = LWP::UserAgent->new(default_headers => $headers);
	$client->timeout(5);
	$client->ssl_opts(verify_hostname => 0);

	my $puturl = sprintf('%s%s', $url,$path);
	my $req = HTTP::Request->new("PUT", $puturl);
	$req->content( $json);
	my $response = $client->request( $req);
	unless ($response->is_success) {
	    die $response->status_line;
	}
	$json = decode_json( $response->content());
	#my $res = $rest->POST($query, $json, {'Content-Type' => 'application/json'});
	#unless ( ($rest->responseCode() < 300) && ($rest->responseCode() >=200)) {
	#    die $rest->responseCode() . ":" . $rest->responseContent();
	#}
    };
    if ($@) {
	my $err = "Error while updating user: $@";
	$self->error_message($err);
	return(undef);
    }
    $json = $self->_SquashJSONBool( $json);
    return( %$json);
}

# Tries to fetch a user's profile from the Globus Online auth
# service using the authentication token passed in
# Sets all the appropriate attributes based on the return values
sub get {
    my $self = shift @_;
    my $token = shift @_;

    my $path = $Bio::KBase::Auth::ProfilePath;
    my $url = $Bio::KBase::Auth::AuthSvcHost;
    my %headers;
    my $method = "GET";
    my ($user_id) = $token =~ /un=(\w+)/;

    unless ($user_id) {
	die "Failed to parse username from un= clause in token. Is the token legit?";
    }

    $headers{'X-GLOBUS-GOAUTHTOKEN'} = $token;
    my $headers = HTTP::Headers->new( %headers);
    
    my $client = LWP::UserAgent->new(default_headers => $headers);
    $client->timeout(5);
    $client->ssl_opts(verify_hostname => 0);
    my $geturl = sprintf('%s%s/%s?custom_fields=*', $url,$path,$user_id);
    my $nuser;

    my $response = $client->get( $geturl);
    unless ($response->is_success) {
	die $response->status_line;
    }
    $nuser = decode_json( $response->content());
    $nuser = $self->_SquashJSONBool( $nuser);
    unless ($nuser->{'username'}) {
	die "No user found by name of $user_id";
    }
    $self->user_id( $nuser->{'username'});
    $self->email( $nuser->{'email'});
    $self->name( $nuser->{'fullname'});
    $self->verified( $nuser->{'email_validated'});
    foreach my $x (keys %{$nuser->{'custom_fields'}}) {
	$self->{$x} = $nuser->{'custom_fields'}->{$x};
    }
    return( $self);
    
}

sub _SquashJSONBool {
    # Walk an object ref returned by from_json() and squash references
    # to JSON::XS::Boolean
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

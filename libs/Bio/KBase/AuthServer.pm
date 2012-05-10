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
    print STDERR Dumper( $OAuthRequest);

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

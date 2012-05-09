package Bio::KBase::AuthClient;

use strict;
use Object::Tiny::RW qw { user logged_in error_msg };
use Bio::KBase::Auth;
use Bio::KBase::AuthUser;
use MIME::Base64;
use Bio::KBase::AuthDirectory;
use JSON;
use Carp qw( croak);
use Net::OAuth;
use Digest::MD5 qw(md5_base64);

# Location of the file where we're storing the authentication
# credentials
# It is a JSON formatted file with the following
# {"oauth_key":"consumer_key_blahblah",
#  "oauth_token":"token_blah_blah",
#  "oauth_secret":"consumer_secret_blahblah"
# }
#

my $auth_rc = "~/.kbase/auth.rc";



sub new() {
    my $class = shift @_;
    my %params = @_;
    my $self = { 'user' => Bio::KBase::AuthUser->new,
		 'oauth_cred' => {},
		 'logged_in' => 0,
		 'error_msg' => ""};
    bless $self,$class;

    # seed the random number generator
    srand(  time ^ $$ );
    # Try calling login to see if creds defined

    eval {
	if (exists($params{ consumer_key})) {
	    $self->login( $params{consumer_key}, $params{consumer_secret});
	    unless ($self->{logged_in}) {
		croak( "Authentication failed:" . $self->error_msg);
	    }
	} elsif (-e $auth_rc && -r $auth_rc) {
	    if (-e $auth_rc && -r $auth_rc) {
		open RC, "<", $auth_rc;
		my @rc = <RC>;
		close RC;
		chomp( @rc);
		my $creds = from_json( join( '',@rc));
		unless ( defined( $creds->{'oauth_key'})) {
		    croak "No oauth_key found in $auth_rc";
		}
		unless ( defined( $creds->{'oauth_secret'})) {
		    croak "No oauth_secret found in $auth_rc";
		}
		unless ($self->login( $creds->{'oauth_key'},$creds->{'oauth_secret'})) {
		    # login failed, pass the error message along. Redundant for now, but
		    # we don't want later code possibly stomping on this result
		    croak "auth_rc credentials failed login: " . $self->{error_msg};
		}
	    }
	}
    };
    if ($@) {
	$self->{error_msg} = $@;
    }
    return($self);
}

sub login() {
    my $self = shift;
    my $oauth_key = shift;
    my $oauth_secret = shift;
    my $creds;
    my $creds2;

    $self->{logged_in} = 0;
    eval {
	if ( $oauth_key && $oauth_secret) {
	    $creds->{'oauth_key'} = $oauth_key;
	    $creds->{'oauth_secret'} = $oauth_secret;
	} elsif (-e $auth_rc && -r $auth_rc) {
	    open RC, "<", $auth_rc;
	    my @rc = <RC>;
	    close RC;
	    chomp( @rc);
	    $creds = from_json( join( '',@rc));
	}

	unless ( defined( $creds->{'oauth_key'})) {
	    croak "No oauth_key found";
	}
	unless ( defined( $creds->{'oauth_secret'})) {
	    croak "No oauth_secret found";
	}
	# This is a not a production-ready way to perform logins, but
	# we're using it here for alpha testing,
	# and must be replaced with oauth protected login before
	# fetching user creds
	my $ad=new Bio::KBase::AuthDirectory;
	my $user = $ad->lookup_consumer( $creds->{'oauth_key'});
	unless ( defined($user->oauth_creds()->{$creds->{'oauth_key'}})) {
	    croak "Could not find matching oauth_key in user database";
	}
	$creds2 = $user->oauth_creds()->{$creds->{'oauth_key'}};
	unless ( $creds2->{'oauth_secret'} eq $creds->{'oauth_secret'}) {
	    croak "oauth_secret does not match";
	}
	$self->{user} =  $user;
	$self->{oauth_cred} = $creds2;
	$self->{logged_in} = 1;
    };
    if ($@) {
	$self->{error_msg} = "Local credentials invalid: $@";
	return(0);
    } else {
	return(1);
    }
}

sub sign_request() {
    my $self = shift;
    my $request = shift;

    # Create the appropriate authorization header with the auth_token
    # call and then push it into the request envelope
    my $authz_hdr = $self->auth_token( $request);

    $request->header( Authorization => $authz_hdr);

    return(1);
}

sub auth_token() {
    my $self = shift;
    my $request = shift;
    my $auth_params = {};

    unless ( defined( $self->{oauth_cred})) {
	carp( "No oauth_cred defined in AuthClient object\n");
	return( undef);
    }
    my $oauth = Net::OAuth->request('consumer')->new(
	consumer_key => $self->{oauth_cred}->{oauth_key},
	consumer_secret => $self->{oauth_cred}->{oauth_secret},
	request_url => $request->uri,
	request_method => $request->method,
	timestamp => time,
	signature_method => 'HMAC-SHA1',
	nonce => md5_base64( map { rand() } (0..4)));
    $oauth->sign;

    return( $oauth->to_authorization_header());
}

sub new_consumer() {
    my $self = shift @_;

    return(1);
}

sub logout(){
    my $self = shift @_;
    return(1);
}

1;

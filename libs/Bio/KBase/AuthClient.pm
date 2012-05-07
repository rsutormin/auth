package Bio::KBase::AuthClient;

use strict;
use Object::Tiny::RW qw { user logged_in error_msg };
use Bio::KBase::Auth;
use Bio::KBase::AuthUser;
use MIME::Base64;
use Bio::KBase::AuthDirectory;
use JSON;
use Carp qw( croak);

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
    my $self = { 'user' => Bio::KBase::AuthUser::new(),
	      'logged_in' => 0,
	      'error_msg' => ""};
    bless $self,$class;

    # Try calling login to see if the creds work
    if (-e $auth_rc && -r $auth_rc) {
	eval {
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
		    croak $self->{error_msg};
		}
	    }
	};
	if ($@) {
	    $self->{error_msg} = "Local credentials invalid: $@";
	}
    }
    return($self);
}

sub login() {
    my $self = shift @_;
    my $oauth_key = shift;
    my $oauth_secret = shift;
    my $creds;
    my $creds2;

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
    };
    if ($@) {
	$self->{error_msg} = "Local credentials invalid: $@";
	return(0);
    } else {
	return(1);
    }
}

sub sign_request() {
    my $self = shift @_;
    my $request = shift;

    return(1);
}

sub auth_token() {
    my $self = shift @_;

    return( encode_base64( "This is a token for " . $self->{'user'}->{'user_id'}));
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

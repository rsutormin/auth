package Bio::KBase::AuthDirectory;

use strict;
use Object::Tiny::RW qw{ error_msg };
use Bio::KBase::AuthUser;
use Bio::KBase::Auth;
use JSON;
use REST::Client;

my $rest = undef;

sub new() {
    my $class = shift;
    my $self = { 'error_msg' => ''};

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


sub lookup_user() {
    my $self= shift;
    my $user_id = shift;
    my $json;
    my $newuser;
    my $query;
    my @attrs;

    if ($user_id) {
	eval {
	    $query = '/profiles/'.$user_id;
	    $rest->GET($query);
	    $json = from_json( $rest->responseContent());
	    # Need to wedge the json response into an authuser object
	    $newuser = new Bio::KBase::AuthUser;
	    @attrs = ( 'user_id','consumer_key','consumer_secret','token',
		       'error_msg','enabled','last_login_time','last_login_ip',
		       'roles','groups','oauth_creds','name','given_name','family_name',
		       'middle_name','nickname','profile','picture','website','email',
		       'verified','gender','birthday','zoneinfo','locale','phone_number',
		       'address','updated_time');
	    foreach  (@attrs) {
		$newuser->{$_} = $json->{$user_id}->{$_};
		# Check for JSON::XS::Boolean references as the return
		# value for a boolean type, and change to simple scalar
		next  unless 'JSON::XS::Boolean' eq ref $newuser->{$_};
		$newuser->{$_} = ( $newuser->{$_} ? 1 : 0 );
	    } 
	};
	if ($@) {
	    print STDERR "Error while fetching user: $@";
	    return( undef);
	}
	return( $newuser );
    } else {
	print STDERR "Did not find user_id";
	return( undef);
    }
}

sub lookup_consumer() {
    my $self= shift;
    my $consumer_key = shift;
    my $json;
    my $newuser;
    my $query;
    my @attrs;
    my $user_id;

    if ($consumer_key) {
	eval {
	    $query = '/oauthkeys/'.$consumer_key;
	    $rest->GET($query);
	    $json = from_json( $rest->responseContent());
	};
	if ($@) {
	    print STDERR "Error while fetching user: $@";
	    return( undef);
	}
	if ($json->{$consumer_key}->{'user_id'}) {
	    $user_id = $json->{$consumer_key}->{'user_id'};
	    return( $self->lookup_user( $user_id));
	} else {
	    print STDERR "Did not find consumer_key $consumer_key";
	    return(undef);
	}
    } else {
	print STDERR "Must specify consumer key";
	return( undef);
    }

}

sub lookup_oauth2_token() {
    my $self= shift;
    my $oauth_token = shift;
    my $json;
    my $newuser;
    my $query;
    my @attrs;
    my $oauth_key_id;

    if ($oauth_token) {
	eval {
	    $query = '/oauthtokens/'.$oauth_token;
	    $rest->GET($query);
	    $json = from_json( $rest->responseContent());
	};
	if ($@) {
	    print STDERR "Error while fetching oauth token: $@";
	    return( undef);
	}
	if ($json->{$oauth_token}->{'oauth_key_id'}) {
	    $oauth_key_id = $json->{$oauth_token}->{'oauth_key_id'};
	    return( $self->lookup_consumer( $oauth_key_id));
	} else {
	    print STDERR "Did not find oauth_token $oauth_token";
	    return(undef);
	}
    } else {
	print STDERR "Must specify oauth token $oauth_token";
	return( undef);
    }
}

sub create_user() {
    my $self= shift;

    return( AuthUser::new() );
}

sub delete_user() {
    my $self= shift;

    return(1);
}

sub enable_user() {
    my $self= shift;

    return(1);
}

sub disable_user() {
    my $self= shift;

    return(1);
}

sub new_consumer() {
    my $self= shift;

    return( {'consumer_key' => 'johnqpublic@nationalab.gov',
	     'consumer_secret' => 'johnqpublics_secret'});
}

sub delete_consumer() {
    my $self= shift;

    return(1);
}

1;

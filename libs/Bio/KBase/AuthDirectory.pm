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
	    } 
	    $self->_SquashJSONBool($newuser)
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
	if ($json->{$oauth_token}->{'oauth_key'}) {
	    $oauth_key_id = $json->{$oauth_token}->{'oauth_key'};
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
    my $newuser = shift;

    unless (ref($newuser) eq "Bio::KBase::AuthUser") {
	$self->{error_message} = "User object required parameter";
	return( undef);
    }
    # perform basic validation of required fields
    my %valid = { 'user_id' => '\w{3,}',
	       'name' => '(-\w\' \.){2,}',
    };
    my @bad = grep { !($newuser->{$_} =~ m/$valid{$_}/) } keys(%valid);
    if ( scalar(@bad) ) {
	$self->{error_message} = "These fields failed validation: "+join(",",@bad);
	return( undef);
    }

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

sub _SquashJSONBool() {
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

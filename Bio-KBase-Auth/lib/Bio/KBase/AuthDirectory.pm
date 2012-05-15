package Bio::KBase::AuthDirectory;

use strict;
use warnings;
use Object::Tiny::RW qw{ error_msg };
use Bio::KBase::AuthUser;
use Bio::KBase::Auth;
use JSON;
use REST::Client;
use Digest::SHA;
use MIME::Base64;

my $rest = undef;

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(
        'error_msg' => '',
    @_);

    eval {
	unless ( defined($rest)) {
	    $rest = new REST::Client( host => $Bio::KBase::Auth::AuthSvcHost);
	}
    };
    if ($@) {
	    # handle exception
    	return;
    } else {
    	return $self;
    }
}

sub error_message {
    my $self = shift;

    return $self->{error_message};
}

sub lookup_user {
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
	    unless ( ($rest->responseCode() < 300) && ($rest->responseCode() >=200)) {
		die $rest->responseCode() . ":" . $rest->responseContent();
	    }
	    $json = from_json( $rest->responseContent());
	    unless ( exists($json->{$user_id})) {
		die "User not found";
	    }
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
	    $self->{error_message} = $@;
	    return;
	}
	    return $newuser;
    } else {
    	print STDERR "Did not find user_id";
	    return;
    }
}

sub lookup_consumer {
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
	    return;
	}
	if ($json->{$consumer_key}->{'user_id'}) {
	    $user_id = $json->{$consumer_key}->{'user_id'};
	    return $self->lookup_user( $user_id);
	} else {
	    print STDERR "Did not find consumer_key $consumer_key";
	    return;
	}
    } else {
	print STDERR "Must specify consumer key";
	return;
    }

}

sub lookup_oauth2_token {
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
	    return;
	}
	if ($json->{$oauth_token}->{'oauth_key'}) {
	    $oauth_key_id = $json->{$oauth_token}->{'oauth_key'};
	    return $self->lookup_consumer( $oauth_key_id);
	} else {
	    print STDERR "Did not find oauth_token $oauth_token";
	    return;
	}
    } else {
	print STDERR "Must specify oauth token $oauth_token";
	return;
    }
}

sub create_user {
    my $self= shift;
    my $newuser = shift;

    unless (ref($newuser) eq "Bio::KBase::AuthUser") {
	$self->{error_message} = "User object required parameter";
	return;
    }
    # perform basic validation of required fields
    my %valid = ( 'user_id', '^\w{3,}$',
		  'name', '^[-\w\' \.]{2,}$',
		  'email', '^\w+\@[\w-]+\.[-\w\.]+$',
	);
    my @bad = grep { ! defined $newuser->{$_} || $newuser->{$_} !~ m/$valid{$_}/ } sort keys(%valid);
    if ( scalar(@bad) ) {
	$self->{error_message} = "These fields failed validation: " . join(",",@bad);
	return;
    }

    # convert the hash into a json string and POST it
    my $unblessed = {%$newuser};
    # get rid of oauth_creds hashref
    delete $unblessed->{oauth_creds};

    my $json = to_json( $unblessed );
    my $res = $rest->POST("/profiles/", $json, {'Content-Type' => 'application/json'});
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
	$self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
	return;
    }
    # Otherwise fetch the entry and return it

    return $self->lookup_user( $newuser->user_id());
}

sub update_user {
    my $self= shift;
    my $newuser = shift;

    unless (ref($newuser) eq "Bio::KBase::AuthUser") {
	$self->{error_message} = "User object required parameter";
	return;
    }

    # make sure the user exists
    unless ( $self->lookup_user( $newuser->user_id())) {
	$self->{error_message} = "User does not exist";
	return;
    }

    # perform basic validation of required fields
    my %valid = ( 'user_id', '^\w{3,}$',
		  'name', '^[-\w\' \.]{2,}$',
		  'email', '^\w+\@[\w-]+\.[-\w\.]+$',
	);
    my @bad = grep { exists($newuser->{$_}) && ! ($newuser->{$_} =~ m/$valid{$_}/) } keys(%valid);
    if ( scalar(@bad) ) {
	$self->{error_message} = "These fields failed validation: " . join(",",@bad);
	return;
    }

    # convert the hash into a json string and POST it
    my $unblessed = {%$newuser};
    # get rid of oauth_creds hashref
    delete $unblessed->{oauth_creds};

    my $json = to_json( $unblessed );
    my $res = $rest->PUT("/profiles/".$newuser->user_id(), $json, {'Content-Type' => 'application/json'});
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
	$self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
	return;
    }
    # Otherwise fetch the entry and return it

    return $self->lookup_user( $newuser->user_id()) ;
}

sub delete_user {
    my $self= shift;
    my $user_id = shift;

    my $res = $rest->DELETE("/profiles/".$user_id);
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
    	$self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
	    return;
    }

    return 1;
}

sub enable_user {
    my $self= shift;
    my $user_id = shift;

    my $json = to_json( { enabled => JSON::true });
    my $res = $rest->PUT("/profiles/" . $user_id, $json, {'Content-Type' => 'application/json'});
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
	$self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
	return;
    }
    return 1;
}

sub disable_user {
    my $self= shift;
    my $user_id = shift;

    my $json = to_json( { enabled => JSON::false });
    my $res = $rest->PUT("/profiles/" . $user_id, $json, {'Content-Type' => 'application/json'});
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
	$self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
    	return;
    }

    return 1;
}

sub new_consumer {
    my $self= shift;
    my $user_id = shift;
    my $key = shift;
    my $secret = shift;

    unless ( $self->lookup_user( $user_id)) {
	    $self->{error_message} = "User not found";
    	return;
    }


    # check to see if we have been given a key, if not
    # then generate one based on username and hex numbers
    srand (time ^ $$ ^ unpack "%L*", `ps axww | gzip -f`);
    unless ($key) {
	$key = $user_id . sprintf( "_%x", (time() + rand())*1000);
    }

    # do the same for the secret, generate a pseudo-random secret
    #
    unless ($secret) {
	$secret = Digest::SHA::sha512_base64(join( '', time(),  map { rand() } (0..10)));
    }

    # push the new consumer key into the profile service
    my $json = to_json( { oauth_key => $key,
			  oauth_secret => $secret,
			  user_id => $user_id});
    my $res = $rest->POST("/oauthkeys/", $json, {'Content-Type' => 'application/json'});
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
	    $self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
    	return;
    }

    return
        {
            'oauth_key'    => $key,
	        'oauth_secret' => $secret
	    };
}

sub delete_consumer {
    my $self= shift;
    my $consumer_key = shift;

    unless ( $self->lookup_consumer( $consumer_key)) {
	$self->{error_message}= "Consumer key not found";
	return;
    }

    my $res = $rest->DELETE("/oauthkeys/".$consumer_key);
    # If we get something other than a 2XX code, flag an error
    if (($rest->responseCode() < 200) || ($rest->responseCode() > 299)) {
	$self->{error_message} = $rest->responseCode() . " : " . $rest->responseContent();
	return;
    }

    return 1;
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

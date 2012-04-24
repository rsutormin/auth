package Bio::KBase::AuthDirectory;

use strict;
use Object::Tiny::RW qw{ error_msg };
use Bio::KBase::AuthUser;
use Bio::KBase::Auth;
use JSON;
use REST::Client;

my $rest = undef;

print "Here!";

sub new() {
    my $class = shift;
    my $self = { 'error_msg' => ''};

    eval {
	unless ( defined($rest)) {
	    print STDERR "Creating rest object rooted at ".$Bio::KBase::Auth::AuthSvcHost;;
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

    return( AuthUser::new() );
}

sub lookup_oauth2_token() {
    my $self= shift;

    return( AuthUser::new() );
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

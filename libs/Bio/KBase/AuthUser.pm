package Bio::KBase::AuthUser;

use strict;
# We use Object::Tiny::RW to generate getters/setters for the attributes
# and save ourselves some tedium
use Object::Tiny::RW qw {
    user_id
    consumer_key
    consumer_secret
    token
    error_msg
    enabled
    last_login_time
    last_login_ip
    roles
    groups
    oauth_creds
    name
    given_name
    family_name
    middle_name
    nickname
    profile
    picture
    website
    email
    verified
    gender
    birthday
    zoneinfo
    locale
    phone_number
    address
    updated_time
};

sub new() {
    my $class = shift;

    # Don't bother with calling the Object::Tiny::RW constructor,
    # since it doesn't do anything except return a blessed empty hash
    my $self  = {};
    bless $self, $class;
  
    # Initialize a few basic things
    $self->{'oauth_creds'} = {};
    $self->{'user_id'} = 'jqpublic';
    return $self;
}

1;

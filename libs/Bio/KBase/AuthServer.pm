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

sub new() {
    my $class = shift;
    my $self = { 'user' => {},
		 'valid' => 1,
		 'auth_protocol' => 'oauth',
		 'error_msg' => '',
    };
    bless $self, $class;

    return($self);
}

sub validate_request() {
    my $self=shift @_;

    return(1);
}

sub validate_auth_token() {
    my $self=shift @_;

    return(1);
}

1;

package Bio::KBase::AuthClient;

use strict;
use Object::Tiny::RW qw { user logged_in error_msg };
use Bio::KBase::AuthUser;
use MIME::Base64;

sub new() {
    my $class = shift @_;
    my $self = { 'user' => Bio::KBase::AuthUser::new(),
	      'logged_in' => 0,
	      'error_msg' => ""};
    bless $self,$class;
    return $self;
}

sub login() {
    my $self = shift @_;

    return(1);
}

sub sign_request() {
    my $self = shift @_;

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

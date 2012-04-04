package AuthClient;

use Object::Tiny::RW qw { user logged_in error_msg };
use AuthUser;
use MIME::Base64;

sub new() {
    $class = shift @_;
    $self = { 'user' => AuthUser::new(),
	      'logged_in' => 0,
	      'error_msg' => ""};
    bless $self,$class;
    return $self;
}

sub login() {
    $self = shift @_;

    return(1);
}

sub sign_request() {
    $self = shift @_;

    return(1);
}

sub auth_token() {
    $self = shift @_;

    return( encode_base64( "This is a token for " . $self->{'user'}->{'user_id'}));
}

sub new_consumer() {
    $self = shift @_;

    return(1);
}

sub logout(){
    $self = shift @_;
    return(1);
}

1;

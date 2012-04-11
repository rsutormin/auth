package AuthDirectory;

use strict;
use Object::Tiny::RW qw{ error_msg };
use AuthUser;

sub new() {
    my $class = shift;
    my $self = { 'error_msg' => ''};
    print "$class\n";
    bless $self, $class;
    return $self;
}


sub lookup_user() {
    my $self= shift;

    return( AuthUser::new() );

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

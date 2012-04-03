package AuthServer;

sub new() {
    my $class = shift;
    my $self = {};
    bless $self, $class;

    return $self;
}

sub validate_request() {
    my $self=shift @_;

}

sub validate_auth_token() {
    my $self=shift @_;

}

1;

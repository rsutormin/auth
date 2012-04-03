package AuthDirectory;

sub new() {
    my $class = shift;
    my $self = {};
    bless $self, $class;

    return $self;
}


sub lookup_user() {
    my $self= shift @_;

}

sub lookup_consumer() {
    my $self= shift @_;

}

sub lookup_oauth2_token() {
    my $self= shift @_;

}

sub create_user() {
    my $self= shift @_;

}

sub delete_user() {
    my $self= shift @_;

}

sub enable_user() {
    my $self= shift @_;

}

sub disable_user() {
    my $self= shift @_;

}

sub new_consumer() {
    my $self= shift @_;

}

sub delete_consumer() {
    my $self= shift @_;

}

1;

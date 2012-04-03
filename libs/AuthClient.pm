package AuthClient;

sub new() {
    $class = shift @_;
    $self = {};
    bless $self,$class;

    return $self;
}

sub login() {
    $self = shift @_;
}

sub sign_request() {
    $self = shift @_;
}

sub auth_token() {
    $self = shift @_;
}

sub new_consumer() {
    $self = shift @_;
}

sub logout(){
    $self = shift @_;
}

1;

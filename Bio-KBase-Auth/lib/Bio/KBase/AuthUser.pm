package Bio::KBase::AuthUser;

use strict;
use warnings;
# We use Object::Tiny::RW to generate getters/setters for the attributes
# and save ourselves some tedium
use Object::Tiny::RW qw {
    token
    error_message
    enabled
    last_login_time
    last_login_ip
    roles
    groups
    oauth_creds
    name
    email
    verified
    updated_time
};

sub new() {
    my $class = shift;

    # Don't bother with calling the Object::Tiny::RW constructor,
    # since it doesn't do anything except return a blessed empty hash
    my $self = $class->SUPER::new(
        'oauth_creds' => {},
        @_
    );

    return($self);
}

sub user_id {
    my $self = shift;
    my $user_id = shift;

    # If there is a user_id value set already, do not accept a new
    # value, just return the old value

    if ($user_id && !(exists $self->{user_id})) {
	$self->{'user_id'} = $user_id;
    }
    return( $self->{'user_id'});
}

1;

__END__

=pod

=head1 Bio::KBase::AuthUser

User object for KBase authentication. Stores user profile and authentication information, including oauth credentials.

This is a container for user attributes - creating, destroying them in the user database is handled by the Bio::KBase::AuthDirectory class.

=head2 Examples

   my $user = Bio::KBase::AuthUser->new()
   # Voila!

=head2 Instance Variables

=over


=item B<user_id> (string)

REQUIRED Identifier for the End-User at the Issuer.

=item B<error_message> (string)

contains error messages, if any, from most recent method call

=item B<enabled> (boolean)

Is this user allowed to login

=item B<last_login_time> (timestamp)

time of last login

=item B<last_login_ip> (ip address)

ip address of last login

=item B<roles> (string array)

An array of strings for storing roles that the user possesses

=item B<groups> (string array)

An array of strings for storing Unix style groups that the user is a member of

=item B<oauth_creds> (hash)

reference to hash array keyed on consumer_keys that stores public keys, private keys, verifiers and tokens associated with this user

=item B<name> (string)

End-User's full name in displayable form including all name parts, ordered according to End-User's locale and preferences.

=item B<email> (string)

The End-User's preferred e-mail address.

=item B<verified> (boolean)

True if the End-User's e-mail address has been verified; otherwise false.

=item B<updated_time> (string)

Time the End-User's information was last updated, represented as a RFC 3339 [RFC3339] datetime. For example, 2011-01-03T23:58:42+0000.

=back

=head2 Methods

=over

=item B<new>()

returns a Bio::KBase::AuthUser reference

=back

=cut

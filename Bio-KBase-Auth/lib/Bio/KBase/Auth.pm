package Bio::KBase::Auth;
#
# Common information across the apps
#
# sychan 4/24/2012
use strict;
use Config::Simple;

our $VERSION = '0.6.0';

our $ConfPath = glob "~/.kbase_config";

my $c = Config::Simple->new( $ConfPath);
our %Conf = $c ? $c->vars() : {};
our %AuthConf = map { $_, $Conf{ $_} } grep /^authentication\./, keys( %Conf);
our $AuthSvcHost = $Conf{'authentication.servicehost'} ?
    $Conf{'authentication.servicehost'} : "https://nexus.api.globusonline.org/";

our $AuthorizePath = $Conf{'authentication.authpath'} ?
    $Conf{'authentication.authpath'} : "/goauth/token";

our $ProfilePath = $Conf{'authentication.profilepath'} ?
    $Conf{'authentication.profilepath'} : "users";

our $RoleSvcURL = $Conf{'authentication.rolesvcurl'} ?
    $Conf{'authentication.rolesvcurl'} : "https://kbase.us/services/authorization/Roles";


# Load a new config file to override the default settings
sub LoadConfig {
    my( $ConfPath) = shift;

    my $c = Config::Simple->new( $ConfPath);
    my %Conf = $c ? $c->vars() : {};
    $AuthSvcHost = $Conf{'authentication.servicehost'} ?
	$Conf{'authentication.servicehost'} : $AuthSvcHost;
    
    $AuthorizePath = $Conf{'authentication.authpath'} ?
	$Conf{'authentication.authpath'} : $AuthSvcHost;
    
    $ProfilePath = $Conf{'authentication.profilepath'} ?
	$Conf{'authentication.profilepath'} : $ProfilePath;
    
    $RoleSvcURL = $Conf{'authentication.rolesvcurl'} ?
	$Conf{'authentication.rolesvcurl'} : $RoleSvcURL;
    
}

1;

__END__
=pod

=head1 Bio::KBase::Auth

OAuth based authentication for Bio::KBase::* libraries.

This is a helper class that stores shared configuration information.

=head2 Class Variables

=over

=item B<$Bio::KBase::Auth::AuthSvcHost>

   This variable contains a URL that points to the authentication service that stores
user profiles. If this is not set properly, the libraries will be unable to reach
the centralized user database and authentication will not work at all.


=item B<$VERSION>

   The version of the libraries.

=item B<$Bio::KBase::Auth::AuthorizePath>

   This variable contains the path on the AuthSvcHost where token authorization
requests are posted.

=item B<$Bio::KBase::Auth::ProfilePath>

   This variable contains the path on the AuthSvcHost where user profile queries
are sent

=item B<$Bio::KBase::Auth::RoleSvcURL>

   The URL for the Roles service, used to retrieve the roles/groups that a user
is associated with.


=item B<$VERSION>

   The version of the libraries.

=back

=cut


use strict;
use warnings;
use Test::More tests => 10 ;
use LWP::UserAgent ;

use lib "/Users/Andi/Development/kbase/auth/Bio-KBase-Auth/lib" ;
use Bio::KBase::AuthToken ;


#
#  Test 1 - Can a new object be created without user?
#

my $object_empty = Bio::KBase::AuthToken->new; # create a new object
ok( defined $object_empty, "Did an object get defined for AuthToken without user" );   

            
#
#  Test 2 - Is the object in the right class?
#
isa_ok( $object_empty, 'Bio::KBase::AuthToken', "Is it in the right class (Bio::KBase::AuthToken)" );   




# my $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest',
# 				    'password' => '@Suite525');




#
#  Test 3 - Are the methods valid?
#

can_ok($object_empty, qw[validate]);


#
# Test 4 Can a new object be created user?
#
my $object = Bio::KBase::AuthToken->new('user_id' => 'kbasetest',
					   'password' => '@Suite525');

ok( defined $object, "Did an object get defined for AuthToken without user" );   

#
#  Test 5 - Is the object in the right class?
#
isa_ok( $object, 'Bio::KBase::AuthToken', "Is it in the right class (Bio::KBase::AuthToken)" );   


#
#  Test 6 - Are the methods valid?
#
can_ok($object, qw[validate]);


#
#  Test 7 - Is the token valid
#

ok( $object->validate() , "Valid token");

# sub testClient {
#    my $server = shift; my $ua = LWP::UserAgent->new();

#    $at = Bio::KBase::AuthToken->new('user_id' => 'kbasetest',
# 'password' => '@Suite525');
#    $ua->default_header( "Authorization" => "OAuth " . $at->token);


#    $res = $ua->get( $server. "someurl" );
#    printf "Client: Recieved a response: %d %s\n", $res->code, $res->content;

#    # As a sanity check, trash the oauth_secret and make sure that
#    # we get a negative result
#    $ua->default_header( "Authorization" => "OAuth Bogotoken");

#    printf "Client: Sending bad request.\n";
#    $res = $ua->get( $server. "someurl" );
#    printf "Client: Recieved a response: %d %s\n", $res->code, $res->content;

# }

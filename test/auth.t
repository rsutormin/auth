use strict;
use warnings;
use Test::More tests => 10 ;
use LWP::UserAgent ;
use JSON;

use lib "/Users/Andi/Development/kbase/auth/Bio-KBase-Auth/lib" ;
use Bio::KBase::AuthToken ;


# test server for authorization
my $server = "http://140.221.92.49:7039/Roles/";

my $json     = JSON->new->allow_nonref;

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
#  Test 4 - Is the token valid
#

ok( !($object_empty->validate()) , "Empty token does not validate");


#
# Test 5 Can a new object be created user?
#
my $object = Bio::KBase::AuthToken->new('user_id' => 'kbasetest',
					'password' => '@Suite525');

ok( defined $object, "Did an object get defined for AuthToken without user" );   

#
#  Test 6 - Is the object in the right class?
#
isa_ok( $object, 'Bio::KBase::AuthToken', "Is it in the right class (Bio::KBase::AuthToken)" );   


#
#  Test 7 - Are the methods valid?
#
can_ok($object, qw[validate token]);


#
#  Test 8 - Is the token valid
#

ok( $object->validate() , "Valid token");


#
# Test authorization
# 

my $ua     = LWP::UserAgent->new();
$ua->default_header( "Authorization" => "OAuth " . $object->token);

#
# Test 9 Test authorization error code
#

my $res = $ua->get( $server. "Roles" );
ok( $res->code , "Request returns error code");

#
# Test 10 Test valid response
#

ok( ($res->code == 200) , "Request is valid");


#
# Test 11 Check content
#
ok( $res->content , 'Received data' );


#
# Test 12 - 15 Check query filter
#
my $filter="filter={ \"members\" : \"sychan\"}" ;
#my $filter='filter={ "members" :{ "$regex" : ".*test.*" }';
my $res = $ua->get( $server. "Roles?$filter" );

ok( $res->code , "Request returns error code");
ok( ($res->code == 200) , "Request is valid");
ok( $res->content , 'Received data' );
ok( ($res->header('Content-Type') eq "application/json") , "Content Type is JSON"); 
    




#
# Test put 
#


#
# Test create role
# 

#
# Test add user
# 

#
# Test retrive role for user
#

#
# Test delete role
#


#
# Test data structure if json
# 

if ($res->header('Content-Type') eq "application/json") {
    my $data = $json->decode( $res->decoded_content ); 
}


my $res = $ua->get( $server. "Roles?$filter" );




printf "Client: Recieved a response: %d %s\n", $res->code, $res->content;

    # ^Roles/(?P<role_id>[^/]+)$
    # ^Roles/?$
    # ^admin/
    # ^authstatus/?$

$res = $ua->get( $server. "Roles" );
$res = $ua->get( $server. "Roles" );
$res = $ua->get( $server. "authstatus" );
$res = $ua->get( $server. "admin" );


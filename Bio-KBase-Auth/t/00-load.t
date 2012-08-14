#!perl -T

use Test::More tests => 4;

BEGIN {
    use_ok( 'Bio::KBase::Auth' ) || print "Bail out!\n";
    use_ok( 'Bio::KBase::AuthToken' ) || print "Bail out!\n";
    use_ok( 'Bio::KBase::AuthClient' ) || print "Bail out!\n";
    use_ok( 'Bio::KBase::AuthUser' ) || print "Bail out!\n";
}

diag( "Testing Bio::KBase::Auth $Bio::KBase::Auth::VERSION, Perl $], $^X" );

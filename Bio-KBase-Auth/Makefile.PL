use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Bio::KBase::Auth',
    AUTHOR              => q{Steve Chan <sychan@lbl.gov>},
    VERSION_FROM        => 'lib/Bio/KBase/Auth.pm',
    ABSTRACT_FROM       => 'lib/Bio/KBase/Auth.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Bio-KBase-Auth-*' },
);

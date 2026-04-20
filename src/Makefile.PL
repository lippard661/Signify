use strict;
use warnings;

use 5.008;

use ExtUtils::MakeMaker;
WriteMakefile
    (
     NAME => 'Signify',
     DISTNAME => 'Signify',
     AUTHOR => 'Jim Lippard <lippard@discord.org>',
     LICENSE => 'BSD',
     PREREQ_PM => {
	 'File::Basename' => '2.85',
	     'File::Copy' => '2.39',
	     'IO::Uncompress::Gunzip' => '2.106'
     },
     PM => { 'Signify.pm' => '$(INST_LIBDIR)/Signify.pm' }
#     TEST_REQUIRES => {
#     }.
#     BUILD_REQUIRES => {
#     },
#     EXE_FILES => [
#     ],
#     META_MERGE => {
#     },
    );

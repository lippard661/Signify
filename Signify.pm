# Module wrapper around OpenBSD signify.
# Written 27-28 July 2024 by Jim Lippard.
# Modified 29 July 2024 by Jim Lippard to not export any names by
#    default and to provide way to skip just the checks for signify
#    executable binary or for other prechecks (except in sign_gzip).
# Modified 31 July 2024 by Jim Lippard so that $require_public_key_file
#    isn't a no-op if $skip_prechecks=1.
# Modified 3 August 2024 by Jim Lippard to return signify error messages
#    from verify and use same "signature not verified: $errmsg" wording
#    in verify_gzip.

# If using OpenBSD::Pledge and OpenBSD::Unveil, the following are
# required:
# pledge: stdio, rpath, proc, exec, unveil
#    tmppath for gzip_verify
# unveil: /usr/bin/signify rx,
#    if using prechecks: pubkey (or dir) r, file r, sigfile r
# temp_dir rwc for gzip_verify and gzip_sign

package Signify;
require 5.003;

use Exporter ();

use strict;
use vars qw(@ERROR @EXPORT @EXPORT_OK @ISA $SIGNIFY_PATH $SIGNIFY_KEY_DIR $VERSION);

use File::Basename qw(fileparse);
use File::Copy qw(copy cp);
use IO::Uncompress::Gunzip;

@ISA = qw(Exporter);
@EXPORT = ();
@EXPORT_OK = qw(sign sign_gzip verify verify_gzip signify_error);

$VERSION = '1.0c';

# Global variables.

# Text of errors from last call to signify.
@ERROR = ();

# Path to signify.
$SIGNIFY_PATH = '/usr/bin/signify';

# Signify keys dir.
$SIGNIFY_KEY_DIR = '/etc/signify';

# Sign a file and create a detached signature file.
# Optionally skip prechecks for signify and existence/readability of
# files.
# Possible errors:
# no executable $SIGNIFY_PATH. $!
# no readable file $file_path. $!
# cannot write signature file $file_path.sig. $!
# no readable secret key $secret_key_path. $!
# signify error
# Last error will be displayed by signify command and not captured in @ERROR.
sub sign {
    my ($file_path, $signify_passphrase, $secret_key_path,
	$skip_signify_check, $skip_prechecks) = @_;

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }
    
    if (!$skip_prechecks) {
	# Need file.
	if (!-r "$file_path") {
	    @ERROR = ("no readable file $file_path. $!\n");
	    return undef;
	}

	# Need signature file to be writeable or nonexistent.
	# This doesn't catch "permission denied" to create,
	# not a missing directory in the path, which the signify
	# command execution will. No $! set.
	# !-w alone will return $! as either Permission denied
	# or No such file or directory (which doesn't distinguish
	# between directory or file), and will not account for
	# immutable flags.
	if (!-w "$file_path.sig" && -e "$file_path.sig") {
	    @ERROR = ("cannot write signature file $file_path.sig.\n");
	    return undef;
	}

	# Need private key.
	if (!-r $secret_key_path) {
	    @ERROR = ("no readable secret key $secret_key_path. $!\n");
	    return undef;
	}
    }

    # Sign.
    if (open (SIGSIGN, '|-', "$SIGNIFY_PATH -S -s $secret_key_path -m $file_path")) {
	print SIGSIGN "$signify_passphrase\n";
	close (SIGSIGN);
    }
    # Can't stop error from displaying here from signify.
    else {
	@ERROR = ("signify error\n");
	return undef;
    }

    return 1;
}

# Verify detached file signature for file and specified public key.
# Optionally skip prechecks for signify and existence/readability of
# files.
# Possible errors:
# Precheck errors (if not $skip_prechecks):
# no executable $SIGNIFY_PATH. $!
# no readable file $file_path. $!
# no readable signature file $file_path.sig. $!
# no readable public key $public_key_path. $!
# Post-signify errors:
# signature not verified: $errmsg
# unexpected signature result, signature not verified. $result
# Errors from signify ($errmsg):
# signify: verification failed: checked against wrong key
# signify: can't open [$file_path|$file_path.sig|$public_key_path]for reading: [No such file or directory|Permission denied]
# signify: invalid comment in $public_key_path; must start with 'untrusted comment: '
sub verify {
    my ($file_path, $public_key_path,
	$skip_signify_check, $skip_prechecks) = @_;
    my ($result);

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }

    if (!$skip_prechecks) {
	# Need file and file signature.
	if (!-r "$file_path") {
	    @ERROR = ("no readable file $file_path. $!\n");
	    return undef;
	}
	if (!-r "$file_path.sig") {
	    @ERROR = ("no readable signature file $file_path.sig. $!\n");
	    return undef;
	}

	# Need public key.
	if (!-r $public_key_path) {
	    @ERROR = ("no readable public key $public_key_path. $!\n");
	    return undef;
	}
    }

    # Verify.
    $result = `$SIGNIFY_PATH -V -p $public_key_path -m $file_path 2>&1`;
    chop ($result);
    if ($?) {
	@ERROR = ("signature not verified: $result\n");
	return undef;
    }
    elsif ($result eq 'Signature Verified') {
	return 1;
    }
    else {
	@ERROR = ("unexpected signature result, signature not verified. $result\n");
	return undef;
    }
}

# Sign a gzipped tar file, in place.
# Must supply path of gzipped tar file, passphrase, secret key path,
# and a temp dir to create the gzipped tar file in. Optionally skip
# signify check and file prechecks.
# Possible errors:
# Pre-signify errors:
# no executable $SIGNIFY_PATH. $!
# no readable secret key $secret_key_path. $!
# no readable gzip $gzip_path. $!
# no writeable gzip $gzip_path. $!
# Post-signify errors:
# failed to sign gzip $gzip_path. $!
# error signing gzip $gzip_path. Zero-length output.
sub sign_gzip {
    my ($gzip_path, $signify_passphrase, $secret_key_path, $temp_dir,
	$skip_signify_check, $skip_prechecks) = @_;

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }

    if (!$skip_prechecks) {
	# Need a readable secret key.
	if (!-r $secret_key_path) {
	    @ERROR = ("no readable secret key $secret_key_path. $!\n");
	    return undef;
	}

	# Need a readable gzipped tar file.
	if (!-r $gzip_path) {
	    @ERROR = ("no readable gzip $gzip_path. $!\n");
	    return undef;
	}

	# Need write permission on gzipped tar file.
	if (!-w $gzip_path) {
	    @ERROR = ("no writeable gzip $gzip_path. $!\n");
	    return undef;
	}
    }

    # Sign the gzip.
    if (!open (SIGNIFYPIPE, '|-', "$SIGNIFY_PATH -Sz -s $secret_key_path -m $gzip_path -x $temp_dir/out.tgz")) {
	@ERROR = ("failed to sign gzip $gzip_path. $!\n");
	return undef;
    }
    print SIGNIFYPIPE "$signify_passphrase\n";
    close (SIGNIFYPIPE);

    # If zero-length, return error and don't overwrite original.
    if (-z "$temp_dir/out.tgz") {
	@ERROR = ("error signing gzip $gzip_path. Zero-length output.\n");
	return undef;
    }
    
    # Copy signed temp file over original.
    copy ("$temp_dir/out.tgz", $gzip_path);

    # Remove temp file.
    unlink ("$temp_dir/out.tgz");
}

# Verify that a gzipped tar file is signed.
# Arguments after $temp_dir are optional.
# Can require a specific public key file name or specific secret key
# pathname in the comment. Can optionally skip check for signify.
# (Don't presently offer a way to skip the other pre- and post-checks.)
# Returns signer and date.
# Possible errors:
# Pre-signify:
# no executable $SIGNIFY_PATH. $!
# Manual gzip review:
# Could not open gzip $gzip_path to verify signature. $!
# gzip header: no signify comment found
# gzip header: untrusted comment public key is "$sig_public_key_file" but required is "$require_public_key_file"
# gzip header: no key path where expected, found "$sig_key"
# gzip header: key directory in comment is "$secret_key_dir" but required is "$require_secret_key_dir"
# gzip header: key file in comment is "$secret_key_file" but required is "$require_secret_key_file"
# Execution errors from signify (via _verify_gzip_signature, see below):
# signature not verified: $errmsg
#   (specific $errmsg possibilities documented on _verify_gzip_signature)
# Post-signify checks:
# signify verified: key directory in gzip header is "$secret_key_dir" but actual signing key directory is "$signer_secret_key_dir"
# signify verified: key file in gzip header is "$secret_key_file" but actual signing key file is "$signer_secret_key_file"
# if $require_secret_key_path
# signify verified: required key directory is "$require_secret_key_dir" but actual signing key directory is "$signer_secret_key_dir"
# signify verified: required key file is "$require_secret_key_file" but actual signing key file is "$signer_secret_key_file"
# if $require_public_key_file && $skip_prechecks
# signify verified: required public key file is "$require_public_key_file" but actual signing key file is "$signer_secret_key_file"
sub verify_gzip {
    my ($gzip_path, $temp_dir,
	$require_public_key_file, $require_secret_key_path,
	$skip_signify_check, $skip_prechecks) = @_;
    my ($sig_comment, $signature, $sig_date, $sig_key);
    my ($sig_public_key_file);
    my ($secret_key_path, $secret_key_dir, $secret_key_file);
    my ($require_secret_key_dir, $require_secret_key_file);
    my ($signer_secret_key_dir, $signer_secret_key_file);
    my ($verified, $errmsg, $signer, $signdate);

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }

    # Might need even if $skip_prechecks.
    ($require_secret_key_file, $require_secret_key_dir) = fileparse ($require_secret_key_path) if (defined ($require_secret_key_path));

    # This pre-checking precludes some of the issues that might come up
    # in _verify_gzip_signature or from signify itself, though those
    # cases are still handled there anyway. This means some error messages
    # will be less precise than they could be.
    # Can skip pre-checks with optional parameter; this also disables
    # the post-checks that are dependent upon gzip comments.

    if (!$skip_prechecks) {
	# Pull out the pubkey name from the comment,
	# the signature, the signing date, and the secret key path.
	if (!open (GZIP, '<', $gzip_path)) {
	    @ERROR = ("Could not open gzip $gzip_path to verify signature. $!\n");
	    return undef;
	}
	seek (GZIP, 0, 10); # skip 10-byte header
	$sig_comment = <GZIP>; # "untrusted comment: verify with <pubkey>.pub"
	$signature = <GZIP>; # <digital signature>
	$sig_date = <GZIP>; # "date=yyyy-mm-ddThh:mm:ssZ"
	$sig_key = <GZIP>; # "key=<path>.sec"
	close (GZIP);

	if ($sig_comment =~ /untrusted comment: verify with ([\w\.-]+)/) {
	    $sig_public_key_file = $1;

	    if (defined ($require_public_key_file) &&
		$sig_public_key_file ne $require_public_key_file) {
		@ERROR = ("gzip header: untrusted comment public key is \"$sig_public_key_file\" but required is \"$require_public_key_file\"\n");
		return undef;
	    }
	
	    if ($sig_key =~ /key=(.*)$/) {
		$secret_key_path = $1;
	    }
	    else {
		@ERROR = ("gzip header: no key path where expected, found \"$sig_key\"\n");
		return undef;
	    }

	    # Used later whether or not require_secret_key_path is used.
	    ($secret_key_file, $secret_key_dir) = fileparse ($secret_key_path); # from gzip header

	    if (defined ($require_secret_key_path)) {
		if ($secret_key_dir ne $require_secret_key_dir) {
		    @ERROR = ("gzip header: key directory in comment is \"$secret_key_dir\" but required is \"$require_secret_key_dir\"\n");
		    return undef;
		}
		if ($secret_key_file ne $require_secret_key_file) {
		    @ERROR = ("gzip header: key file in comment is \"$secret_key_file\" but required is \"$require_secret_key_file\"\n");
		    return undef;	
		}
	    }
	}

	($verified, $errmsg, $signer, $signdate) = &_verify_gzip_signature ($gzip_path, $temp_dir);

	if (!$verified) {
	    @ERROR = ("signature not verified: $errmsg\n");
	    return undef;
	}

	# Check again to make sure signer matches the comment in gzip header.
	($signer_secret_key_file, $signer_secret_key_dir) = fileparse ($signer);

	if (!$skip_prechecks) {
	    if ($signer_secret_key_dir ne $secret_key_dir) {
		@ERROR = ("signify verified: key directory in gzip header is \"$secret_key_dir\" but actual signing key directory is \"$signer_secret_key_dir\"\n");
		return undef;
	    }
	    if ($signer_secret_key_file ne $secret_key_file) {
		@ERROR = ("signify verified: key file in gzip header is \"$secret_key_file\" but actual signing key file is \"$signer_secret_key_file\"\n");
		return undef;
	    }
	}

	# Signer must match required.
	if (defined ($require_secret_key_path)) {
	    if ($signer_secret_key_dir ne $require_secret_key_dir) {
		@ERROR = ("signify verified: required key directory is \"$require_secret_key_dir\" but actual signing key directory is \"$signer_secret_key_dir\"\n");
		return undef;
	    }
	    if ($signer_secret_key_file ne $require_secret_key_file) {
		@ERROR = ("signify verified: required key file is \"$require_secret_key_file\" but actual signing key file is \"$signer_secret_key_file\"\n");
		return undef;
	    }
	}

	# So $require_public_key_file isn't a no-op if $skip_prechecks = 1
	if (defined ($require_public_key_file) && $skip_prechecks) {
	    my $temp_require_secret_key_file = $require_public_key_file;
	    $temp_require_secret_key_file =~ s/\.pub$/.sec/;
	    if ($signer_secret_key_file ne $temp_require_secret_key_file) {
		@ERROR = ("signify verified: required public key file is \"$require_public_key_file\" but actual signing key file is \"$signer_secret_key_file\"\n");
		return undef;
	    }
	}



	return ($signer, $signdate);
    }

    # No comment found--perhaps not a gzip, not signed.
    # This precludes some of the possible signify responses.
    @ERROR = ("gzip header: no signify comment found\n");
    return undef;
}

# Subroutine originally from distribute.pl and install.pl which had to
# be manually kept consistent before moving to separate module.
# Subroutine to verify signature on gzip file.
# Now relies on underlying verify_gzip_signature and gzip_uncompress.

# Subroutine to verify signify signature on a gzip archive.
# Input: existing temp dir and filename of gzip archive.
# Return values: $verified (0=no, 1=yes), $msg, $signer, $signdate
# $signer and $signdate are undefined if not verified (currently
#    it will return any signer or signdate found in gzip header even
#    if not verified)
# $errmsg is undefined if verified, otherwise:
#    "no file" (if file doesn't exist)
#    "unsigned gzip archive" (if a gzip but not signed)
#    "gzheader truncated" (if gzip malformed)
#    "not a gzip" (if doesn't have gzip header)
#    "bad signature" (signature parse error or wrong sig, signify will produce specific error)
#    "signature mismatch" (good sig/key but bad data, signify will produce error)
#    "no exec of signify" (if child exec of signify fails, will also
#       send error message to STDERR)
sub _verify_gzip_signature {
    my ($file, $temp_dir) = @_;
    my ($verified, $errmsg, $signer, $signdate);

    $verified = 0;

    return ($verified, 'no file') if (!-e $file);

    # Open write pipe to child process.
    my $pid = open (my $fh, '-|');
    if ($pid) { # parent
	($signer, $signdate) = &_gzip_uncompress ($file, $fh);
	close ($fh);
	if (open (FILE, '<', "$temp_dir/$file.err")) {
	    $errmsg = <FILE>;
	    close (FILE);
	    unlink ("$temp_dir/$file.err");
	    if ($errmsg =~ /signify: unsigned gzip archive/) {
		$errmsg = 'unsigned gzip archive';
	    }
	    elsif ($errmsg =~ /signify: invalid magic in gzheader/) {
		$errmsg = 'not a gzip';
	    }
	    elsif ($errmsg =~ /signify: gzheader truncated/) {
		$errmsg = 'gzheader truncated';
	    }
	    elsif ($errmsg =~ /signify: signature mismatch/) {
		$errmsg = 'signature mismatch';
	    }
	    else {
		# other possibilities?
		chop ($errmsg);
	    }
	}
	else { # no error msg file
	    # $? has child exit status, need to shift right 8 bits
	    # $? & 127 is signal number for child termination
	    # $? & 128 is 1 if core dumped
	    my $child_exit_status = $? >> 8;
	    if ($child_exit_status) {
		if ($child_exit_status == 1) {
		    # signify: verification failed: checked against wrong key
		    # signify: unable to parse
		    $errmsg = 'bad signature';
		}
		elsif ($child_exit_status == 2) {
		    $errmsg = 'no exec of signify';
		}
		elsif ($child_exit_status == 4) {
		    # could potentially be other signify errors?
		    $errmsg = 'signature mismatch';
		}
		else {
		    $errmsg = "no exec of signify: $child_exit_status";
		}
	    }
	    else { # only case where verified
		$verified = 1;
	    }
	}
	return ($verified, $errmsg, $signer, $signdate);
    }
    else { # child
	# Send STDERR to temp file for retrieval by parent.
	open (STDERR, '>', "$temp_dir/$file.err");
	# Run signify on the gzip file stream.
	exec ($SIGNIFY_PATH, '-zV', '-x', $file) or die "Could not exec $SIGNIFY_PATH. $!\n";
    }
}

# Subroutine to uncompress a gzip file after first examining the header.
# Borrowed from OpenBSD::PackageRepository.pm, more or less--stripped down.
sub _gzip_uncompress {
    my ($file) = @_;
    my ($signer, $signdate);

    my $fh = IO::Uncompress::Gunzip->new($file, MultiStream => 1);
    my $h = $fh->getHeaderInfo;
    if ($h) {
	for my $line (split /\n/, $h->{Comment}) {
	    if ($line =~ m/^key=(.*)$/) {
		$signer = $1;
	    }
	    elsif ($line =~ m/^date=(.*)$/) {
		$signdate = $1;
	    }
	}
    }
    else { # not a gzip header
	$fh->close;
	return undef;
    }
    $fh->close;
    return ($signer, $signdate);
}

sub signify_error {
    wantarray ? @ERROR : join ('', @ERROR);
}

# Module return value. Make sure module returns true.
1;


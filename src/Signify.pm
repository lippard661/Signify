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
# Modified 13 September 2025 by Jim Lippard to use signify-openbsd if
#    running on Linux.
# Modified 22 October 2025 by Jim Lippard to accept either "/etc/signify"
#    or  "./" as a key directory since it is no longer set by pkg_sign
#    as of OpenBSD 7.8.
# Modified 8 November 2025 by Jim Lippard to avoid shell on file opens,
#    use chomp instead of chop, use randomly named temp files instead
#    of static names for gzip handling, remove use of backticks with
#    IPC::Open3, examine gzip header with IO::Uncompress::Gunzip instead
#    of manually and avoid dependence on comment field order.
# Modified 9 November 2025 by Jim Lippard to fix tempfile handling, fix
#    broken gzip verification, and some other lesser issues.
# Modified 11 November 2025 by Jim Lippard to support macOS location of
#    signify (via Homebrew) and remove some but not all gzip header
#    check redundancy.
# Modified 1 January 2026 by Jim Lippard to initialize @ERROR in each
#    subroutine (except signify_errors).
# Modified 4 January 2026 by Jim Lippard to remove & from subroutine calls.
# Modified 10 January 2026 by Jim Lippard to remove excess quotes.
# Modified 20 April 2026 by Jim Lippard to check copy result and return
#    error from sign_gzip.
# Modified 17 May 2026 by Jim Lippard after Gemini security review to
#    ensure tempfiles removed in early returns from _verify_gzip_signature,
#    avoid potential IPC::Open3 deadlock in verify by merging STDOUT/STDERR,
#    ensure tempfile removal in sign_gzip, and remove unnecessary conditional
#    on basename call in _verify_gzip_signature. Change bareword filehandles
#    to $fh format (except for STDOUT/STDERR).

# If using OpenBSD::Pledge and OpenBSD::Unveil, the following are
# required:
# pledge: stdio, rpath, proc, exec, unveil
#    tmppath for gzip_verify
# unveil: /usr/bin/signify rx,
#    if using prechecks: pubkey (or dir) r, file r, sigfile r
# temp_dir rwc for gzip_verify and gzip_sign
# /dev/null rwc for gzip_verify

package Signify;
require 5.003;

use Exporter ();

use strict;
use warnings;
use vars qw(@ERROR @EXPORT @EXPORT_OK @ISA $SIGNIFY_PATH $SIGNIFY_KEY_DIR $ALT_KEY_DIR $VERSION);

use File::Basename qw(fileparse basename dirname);
use File::Copy qw(copy cp);
use File::Temp qw(tempfile);
use IO::Uncompress::Gunzip;
use IPC::Open3;

@ISA = qw(Exporter);
@EXPORT = ();
@EXPORT_OK = qw(sign sign_gzip verify verify_gzip signify_error);

$VERSION = '1.2';

# Global variables.

# Text of errors from last call to signify.
@ERROR = ();

# Path to signify.
$SIGNIFY_PATH = '/usr/bin/signify';

# Debian path to signify.
$SIGNIFY_PATH = '/usr/bin/signify-openbsd' if $^O eq 'linux';

# macOS path to signify.
$SIGNIFY_PATH = '/opt/homebrew/bin/signify' if $^O eq 'darwin';

# Signify keys dir.
$SIGNIFY_KEY_DIR = '/etc/signify';
$ALT_KEY_DIR = './';

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

    @ERROR = ();

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }
    
    if (!$skip_prechecks) {
	# Need file.
	if (!-r $file_path) {
	    @ERROR = ("no readable file $file_path. $!\n");
	    return undef;
	}

	# Need signature file to be writeable or nonexistent.
	# This previously didn't catch "permission denied" to create,
	# nor a missing directory in the path, which the signify
	# command execution will. No $! set.
	# !-w alone will return $! as either Permission denied
	# or No such file or directory (which doesn't distinguish
	# between directory or file), and will not account for
	# immutable flags.
	if (-e "$file_path.sig") {
	    unless (-w "$file_path.sig") { @ERROR = ("cannot write signature file $file_path.sig\n"); return undef; }
	}
	else { # check dir exists and is writeable
	    my $dir = dirname ($file_path);
	    unless (-d $dir && -w $dir) { @ERROR = ("cannot create signature file in directory dir\n"); return undef; }
	}

	# Need private key.
	if (!-r $secret_key_path) {
	    @ERROR = ("no readable secret key $secret_key_path. $!\n");
	    return undef;
	}
    }

    # Sign.
    if (open (my $sigsign_fh, '|-', $SIGNIFY_PATH, '-S', '-s', $secret_key_path, '-m', $file_path)) {
	print $sigsign_fh "$signify_passphrase\n";
	close ($sigsign_fh);
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
# failed to exec signify $@
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

    @ERROR = ();

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }

    if (!$skip_prechecks) {
	# Need file and file signature.
	if (!-r $file_path) {
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
    my ($pid, $out);
    eval {
	# merge STDOUT/STDERR since they aren't distinguished
	$pid = open3 (undef, $out, $out, $SIGNIFY_PATH, '-V', '-p', $public_key_path, '-m', $file_path);
    };
    if ($@) { @ERROR = ("failed to exec signify: $@"); return undef; }
    my $outstr = do { local $/; <$out> // '' };
    waitpid ($pid, 0);
    my $exit = $? >> 8;
    chomp ($outstr);
    if ($exit != 0) {
	my $msg = $outstr; # STDOUT and STDERR
	@ERROR = ("signature not verified: $msg\n");
	return undef;
    }
    elsif ($outstr =~ /Signature\s+Verified/i) {
	return 1;
    }
    else {
	@ERROR = ("unexpected signature result, signature not verified. $outstr\n");
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
# failed to copy signed gzip to $gzip_path. $!
sub sign_gzip {
    my ($gzip_path, $signify_passphrase, $secret_key_path, $temp_dir,
	$skip_signify_check, $skip_prechecks) = @_;
    my ($temp_file, $tempfh);

    @ERROR = ();

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

    # Random filename.
    ($tempfh, $temp_file) = tempfile ('signify.XXXXXXXX', SUFFIX => '.tgz', DIR => $temp_dir, UNLINK => 1);
    close ($tempfh);

    # Sign the gzip.
    my $signifypipe_fh;
    if (!open ($signifypipe_fh, '|-', $SIGNIFY_PATH, '-Sz', '-s', $secret_key_path, '-m', $gzip_path, '-x', "$temp_file")) {
	@ERROR = ("failed to sign gzip $gzip_path. $!\n");
	return undef;
    }
    print $signifypipe_fh "$signify_passphrase\n";
    close ($signifypipe_fh);

    # If zero-length, return error and don't overwrite original.
    if (-z $temp_file) {
	@ERROR = ("error signing gzip $gzip_path. Zero-length output.\n");
	return undef;
    }
    
    # Copy signed temp file over original.
    unless (copy ($temp_file, $gzip_path)) {
	@ERROR = ("failed to copy signed gzip to $gzip_path. $!\n");
	return undef;
    }

    # $temp_file is removed automatically.
    return 1;
}

# Verify that a gzipped tar file is signed.
# Arguments after $temp_dir are optional.
# Can require a specific public key file name or specific secret key
# pathname in the comment. Can optionally skip check for signify.
# Specified public key and secret key names must match each other and
# the key name in the gzip header comment (which must match the private
# key name). If not specified, the gzip header key file name, but
# with .pub, is looked for in /etc/sigtree, and that's the only actual
# verification that will be attempted.
# (Don't presently offer a way to skip the other pre- and post-checks.)
# Returns signer and date.
# Possible errors:
# Pre-signify:
# no executable $SIGNIFY_PATH. $!
# mismatch of required public key and secret key filenames.
# Manual gzip review:
# Could not open gzip $gzip_path to verify signature. $!
# no gzip header found
# gzip header: no signify comment found
# gzip header: untrusted comment public key is "$sig_public_key_file" but required is "$require_public_key_file"
# gzip header: no key path found
# gzip header: no signature date found
# gzip header: key directory in comment is "$secret_key_dir" but required is "$require_secret_key_dir"
# gzip header: key file in comment is "$secret_key_file" but required is "$require_secret_key_file"
# gzip header: mismatch of public key and secret key filenames. [only in precheck]
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
    my ($sig_comment, $sig_date);
    my ($sig_public_key_file);
    my ($secret_key_path, $secret_key_dir, $secret_key_file);
    my ($require_secret_key_dir, $require_secret_key_file);
    my ($signer_secret_key_dir, $signer_secret_key_file);
    my ($verified, $errmsg, $signer, $signdate);

    @ERROR = ();

    if (!$skip_signify_check) {
	# Need signify.
	if (!-x $SIGNIFY_PATH) {
	    @ERROR = ("no executable $SIGNIFY_PATH. $!\n");
	    return undef;
	}
    }

    # Might need even if $skip_prechecks.
    if (defined ($require_secret_key_path)) {
	($require_secret_key_file, $require_secret_key_dir) = fileparse ($require_secret_key_path);
	# Can't have mismatch.
	if (defined ($require_public_key_file)) {
	    my $pubkey = $require_public_key_file;
	    $pubkey =~ s/\.pub$//;
	    my $seckey = $require_secret_key_file;
	    $seckey =~ s/\.sec$//;
	    if ($pubkey ne $seckey) {
		@ERROR = ('mismatch of required public key and secret key filenames.\n');
		return undef;
	    }
	}
    }

    # This pre-checking precludes some of the issues that might come up
    # in _verify_gzip_signature or from signify itself, though those
    # cases are still handled there anyway. This means some error messages
    # will be less precise than they could be.
    # Can skip pre-checks with optional parameter; this also disables
    # the post-checks that are dependent upon gzip comments.

    if (!$skip_prechecks) {
	# Check comment details in header. Used to do this with manual examination of gzip header.
	($secret_key_path, $sig_date, $sig_comment, $errmsg) = _gzip_get_header ($gzip_path);
	if (defined ($errmsg)) {
	    @ERROR = ($errmsg);
	    return undef;
	}

	# Do a few checks on header contents.
	if (!defined ($sig_comment)) {
	    @ERROR = ("gzip header: no signify comment found\n");
	    return undef;
	}
	elsif ($sig_comment =~ /untrusted comment: verify with ([\w\.-]+)/) {
	    $sig_public_key_file = $1;

	    if (defined ($require_public_key_file) &&
		$sig_public_key_file ne $require_public_key_file) {
		@ERROR = ("gzip header: untrusted comment public key is \"$sig_public_key_file\" but required is \"$require_public_key_file\"\n");
		return undef;
	    }
	
	    if (!defined ($secret_key_path)) {
		@ERROR = ("gzip header: no key path found\n");
		return undef;
	    }

	    if (!defined ($sig_date)) {
		@ERROR = ("gzip header: no signature date found\n");
		return undef;
	    }

	    # Used later whether or not require_secret_key_path is used.
	    ($secret_key_file, $secret_key_dir) = fileparse ($secret_key_path); # from gzip header

	    # Mismatch of gzip header public and secret file names.
	    my $gzip_pubkey = $sig_public_key_file;
	    $gzip_pubkey =~ s/\.pub$//;
	    my $gzip_seckey = $secret_key_file;
	    $gzip_seckey =~ s/\.sec$//;
	    if ($gzip_pubkey ne $gzip_seckey) {
		@ERROR = ('gzip header: mismatch of public key and secret key filenames.\n');
		return undef;
	    }

	    if (defined ($require_secret_key_path)) {
		if ($require_secret_key_dir ne $ALT_KEY_DIR &&
		    $secret_key_dir ne $require_secret_key_dir &&
		    $secret_key_dir ne $SIGNIFY_KEY_DIR &&
		    $secret_key_dir ne $ALT_KEY_DIR) {
		    @ERROR = ("gzip header: key directory in comment is \"$secret_key_dir\" but required is \"$require_secret_key_dir\"\n");
		    return undef;
		}
		if ($secret_key_file ne $require_secret_key_file) {
		    @ERROR = ("gzip header: key file in comment is \"$secret_key_file\" but required is \"$require_secret_key_file\"\n");
		    return undef;	
		}
	    }
	}
    }

    ($verified, $errmsg, $signer, $signdate) = _verify_gzip_signature ($gzip_path, $temp_dir);

    if (!$verified) {
	@ERROR = ("signature not verified: $errmsg\n");
	return undef;
    }

    # Check again to make sure signer matches the comment in gzip header.
    ($signer_secret_key_file, $signer_secret_key_dir) = fileparse ($signer);
    
    if (!$skip_prechecks) {
	if ($secret_key_dir ne $ALT_KEY_DIR &&
	    $signer_secret_key_dir ne $secret_key_dir &&
	    $signer_secret_key_dir ne $SIGNIFY_KEY_DIR &&
	    $signer_secret_key_dir ne $ALT_KEY_DIR) {
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
	if ($require_secret_key_dir ne $ALT_KEY_DIR &&
	    $signer_secret_key_dir ne $require_secret_key_dir &&
	    $signer_secret_key_dir ne $SIGNIFY_KEY_DIR &&
	    $signer_secret_key_dir ne $ALT_KEY_DIR) {
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

# Subroutine originally from distribute.pl and install.pl which had to
# be manually kept consistent before moving to separate module.
# Subroutine to verify signature on gzip file.
# Now relies on underlying verify_gzip_signature and gzip_uncompress.

# Subroutine to verify signify signature on a gzip archive.
# Input: existing temp dir and filename of gzip archive. (Ignores required
# key fields, those are just pre-checks.)
# Return values: $verified (0=no, 1=yes), $msg, $signer, $signdate
# $signer and $signdate are undefined if not verified (currently
#    it will return any signer or signdate found in gzip header even
#    if not verified)
# $errmsg is undefined if verified, otherwise:
#    "could not open gzip <file>. <reason>"
#    "no file" (if file doesn't exist)
#    "no public key: <keyname>" (if signing key's public key not on system)
#    "unsigned gzip archive" (if a gzip but not signed)
#    "gzheader truncated" (if gzip malformed)
#    "no gzip header found" (if doesn't have gzip header)
#    "bad signature" (signature parse error or wrong sig, signify will produce specific error)
#    "signature mismatch" (good sig/key but bad data, signify will produce error)
#    "no exec of signify" (if child exec of signify fails, will also
#       send error message to STDERR)
sub _verify_gzip_signature {
    my ($file, $temp_dir) = @_;
    my ($verified, $errmsg, $signer, $signdate, $comment,
	$signer_pubkey,
	$temp_file, $tempfh,
	$errfile_opened);
    my $buffsize = 2 * 1024 * 1024;

    $verified = 0;
    $errfile_opened = 0;

    return ($verified, 'no file') if (!-e $file);

    # Get signer from gzip header.
    ($signer, $signdate, $comment, $errmsg) = _gzip_get_header ($file);
    if (defined ($signer)) {
	$signer_pubkey = $signer;
	$signer_pubkey =~ s/\.sec$/\.pub/;
	$signer_pubkey = basename ($signer_pubkey);
    }

    if (defined ($errmsg)) {
	return ($verified, $errmsg);
    }

    if (!-e "$SIGNIFY_KEY_DIR/$signer_pubkey") {
	$errmsg = "no public key $signer_pubkey";
	return ($verified, $errmsg, $signer, $signdate);
    }

    # Get random filename for returning error from child.
    ($tempfh, $temp_file) = tempfile ('signify.XXXXXXXX', DIR => $temp_dir, UNLINK => 0);
    close ($tempfh);

    # Open read/write pipe.
    pipe (my $readfh, my $writefh) or do {
	unlink ($temp_file);
	die "pipe failed: $!\n";
    };
    my $pid = fork();
    if (!defined ($pid)) {
	unlink ($temp_file);
	die "fork failed: $!\n";
    }
    if ($pid) { # parent
	close ($readfh); # won't read from pipe
	
	# Send gzip to child.
	open (my $gzfh, '<', $file) or
	    do { $errmsg = "could not open gzip $file. $!";
		 unlink ($temp_file);
		 return ($verified, $errmsg, $signer, $signdate); };
	binmode ($gzfh);
	# using perl i/o instead of sysread
	# if there are opportunities to improve efficiency they might
	# be here, this is slow (with both read and sysread).
	while (read ($gzfh, my $buf, $buffsize)) {
	    print $writefh $buf or last;
	}
	close ($gzfh);
	close ($writefh);

	waitpid ($pid, 0);

	# Check child's error output, then child exit status.
	if (open (my $errfile, '<', $temp_file)) {
	    $errfile_opened = 1;
	    $errmsg = do { local $/; <$errfile>; };
	    close ($errfile);
	    unlink ($temp_file);
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
	}
	if (!$errfile_opened || $errmsg eq '') {
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
	# Close write side of pipe.
	close ($writefh);
	# Open STDIN from read side of pipe and close readfh.
	open (STDIN, '<&', $readfh) or die "dup2 filed: $!\n";
	close ($readfh);
	# Send STDERR to temp file for retrieval by parent.
	open (STDERR, '>', $temp_file);
	# Send STDOUT to /dev/null.
	open (STDOUT, '>', '/dev/null');
	# Run signify on the gzip file stream.
	exec ($SIGNIFY_PATH, '-zV', '-p', "$SIGNIFY_KEY_DIR/$signer_pubkey") or die "Could not exec $SIGNIFY_PATH. $!\n";
	# exec doesn't return.
    }
}

# Subroutine to uncompress a gzip file after first examining the header.
# Borrowed from OpenBSD::PackageRepository.pm, more or less--stripped down.
# Returns $signer, $signdate, $comment, $errmsg.
# gzip header format:
# 10-byte header
# comment field which is newline-separated values:
# untrusted comment: verify with <pubkey>.pub
# <digital signature>
# date=yyyy-mm-ddThh:mm:ssZ
# key=<path>.sec [now changed to be basename.sec, no path]
sub _gzip_get_header {
    my ($file) = @_;
    my ($signer, $signdate, $comment);

    my $gzip_fh = IO::Uncompress::Gunzip->new($file, MultiStream => 1) or
	do { return (undef, undef, undef, "could not open gzip $file. $!"); };
    
    my $hdrinfo = $gzip_fh->getHeaderInfo;
    if ($hdrinfo && defined ($hdrinfo->{Comment})) {
	for my $line (split /\n/, $hdrinfo->{Comment}) {
	    $comment = $line if ($line =~ /untrusted comment:/);
	    $signer = $1 if ($line =~ /^key=(.*)$/);
	    $signdate = $1 if ($line =~ /^date=(.*)$/);
	}
    }
    else { # not a gzip header
	$gzip_fh->close;
	return (undef, undef, undef, 'no gzip header found');
    }
    $gzip_fh->close;
    return ($signer, $signdate, $comment, undef);
}

sub signify_error {
    wantarray ? @ERROR : join ('', @ERROR);
}

# Module return value. Make sure module returns true.
1;

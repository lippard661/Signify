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
# Modified 19 May 2026 by Jim Lippard to add get_gzip_signer.
# Modified 14 October 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard after review against the audit checklist (version 1.3):
#    _verify_gzip_signature ignores SIGPIPE in the parent while streaming,
#    so a tampered or wrong-key package no longer kills the caller; treats
#    signify killed by a signal (or a failed waitpid) as not verified
#    instead of verified; the forked child reports exec/dup failures and
#    leaves with POSIX::_exit instead of die, so the caller's END blocks
#    and code never run in the child; rejects a gzip header with no usable
#    key name. sign_gzip writes the signed output to a temp file beside
#    the original and renames it into place (keeping the original's mode
#    and owner), so a failure can no longer truncate the original; it no
#    longer uses $temp_dir. sign and sign_gzip check signify's exit status
#    and ignore SIGPIPE while sending the passphrase. Fixed literal "\n"
#    in two error messages and "directory dir" in sign. Corrected the
#    pledge/unveil notes and the required Perl version. Added a
#    named-argument form to sign, verify, sign_gzip and verify_gzip; the
#    positional form still works and is to be removed once all callers
#    (install.pl, distribute.pl, reportnew, sigtree.pl) use the named
#    form.
# Modified 15 October 2026 by Claude Opus 5.5 at the direction of Jim
#    Lippard (version 1.4): sign and sign_gzip send the passphrase with
#    syswrite instead of print. With a key made with signify -n, signify
#    can exit before reading it; the buffered print was then flushed by
#    close, the flush failed with EPIPE, and Perl's close set $? to -1,
#    so a successful signing was reported as "signify failed could not
#    be run" (measured: 10-21% of signings under load). Not 1.3a: a
#    non-numeric $VERSION makes Signify->VERSION ('1.3') die, which
#    callers use as their version check.

# Calling (named form; the second argument is a hash reference):
#    sign ($file, { secret_key_path => $sec, passphrase => $pw,
#                   skip_signify_check => 0, skip_prechecks => 0 })
#    verify ($file, { public_key_path => $pub,
#                     skip_signify_check => 0, skip_prechecks => 0 })
#    sign_gzip ($gzip, { secret_key_path => $sec, passphrase => $pw,
#                        skip_signify_check => 0, skip_prechecks => 0 })
#    verify_gzip ($gzip, { temp_dir => $dir,
#                          require_public_key_file => 'x-pkg.pub',
#                          require_secret_key_path => '/etc/signify/x-pkg.sec',
#                          skip_signify_check => 0, skip_prechecks => 0 })
# secret_key_path, public_key_path and temp_dir are required where shown;
# passphrase defaults to '' (for a key made with signify -n); the rest
# are optional. An unknown name, a missing required name, or anything
# after the hash is an error (returns undef, message in signify_error).
# The positional form (deprecated) is detected by a second argument
# that is not a hash reference; its arguments are as documented on each
# subroutine below.

# If using OpenBSD::Pledge and OpenBSD::Unveil, these are the accesses
# the module's own Perl code makes (signify runs after exec):
# pledge: stdio, rpath, proc, exec
#    wpath, cpath for verify_gzip (temp file in temp_dir) and sign_gzip
#       (temp file beside the gzip, rename over it)
#    fattr for sign_gzip (sets the original's mode on the new file)
#    chown for sign_gzip only when running as root on a gzip owned by
#       another user or group
#    unveil, if the caller calls unveil after loading.
# unveil: $SIGNIFY_PATH rx (rx, not x: it is file-tested with -x unless
#       $skip_signify_check),
#    verify_gzip: $SIGNIFY_KEY_DIR (/etc/signify) r always (the signer's
#       public key is tested there whether or not prechecks are skipped),
#       the gzip r, temp_dir rwc,
#    sign_gzip: the gzip's directory rwc, secret key r,
#    sign: file r, the file's directory rwc, secret key r,
#    verify: file r, sigfile r, public key r.
# /dev/null needs no unveil (the kernel lets it bypass unveil).
# SIGPIPE: callers need not set $SIG{PIPE}; the module ignores it locally
#    wherever it writes to signify.

package Signify;
require 5.010;

use Exporter ();

use strict;
use warnings;
use vars qw(@ERROR @EXPORT @EXPORT_OK @ISA $SIGNIFY_PATH $SIGNIFY_KEY_DIR $ALT_KEY_DIR $VERSION);

use File::Basename qw(fileparse basename dirname);
use File::Temp qw(tempfile);
use IO::Uncompress::Gunzip;
use IPC::Open3;
use POSIX ();

@ISA = qw(Exporter);
@EXPORT = ();
@EXPORT_OK = qw(get_gzip_signer sign sign_gzip verify verify_gzip signify_error);

$VERSION = '1.4';

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
# signify failed (exit N)|(killed by signal N)
# signify's own message is displayed by the signify command and not
# captured in @ERROR.
sub sign {
    my ($file_path, $signify_passphrase, $secret_key_path,
	$skip_signify_check, $skip_prechecks);
    if (ref ($_[1]) eq 'HASH') {
	my $arg = _named_args ('sign', \@_, ['secret_key_path'],
			       ['passphrase', 'skip_signify_check', 'skip_prechecks'])
	    or return undef;
	$file_path = $_[0];
	($signify_passphrase, $secret_key_path,
	 $skip_signify_check, $skip_prechecks) =
	    @{$arg}{qw(passphrase secret_key_path skip_signify_check skip_prechecks)};
	$signify_passphrase //= '';
    }
    else { # positional form (deprecated)
	($file_path, $signify_passphrase, $secret_key_path,
	 $skip_signify_check, $skip_prechecks) = @_;
    }

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
	    unless (-d $dir && -w $dir) { @ERROR = ("cannot create signature file in directory $dir\n"); return undef; }
	}

	# Need private key.
	if (!-r $secret_key_path) {
	    @ERROR = ("no readable secret key $secret_key_path. $!\n");
	    return undef;
	}
    }

    # Sign.
    my $sigsign_fh;
    # Can't stop error from displaying here from signify.
    if (!open ($sigsign_fh, '|-', $SIGNIFY_PATH, '-S', '-s', $secret_key_path, '-m', $file_path)) {
	@ERROR = ("signify error\n");
	return undef;
    }
    if (!_send_passphrase_and_close ($sigsign_fh, $signify_passphrase)) {
	@ERROR = ('signify failed ' . _describe_status ($?) . "\n");
	return undef;
    }

    return 1;
}

# Named-argument form, used by every public subroutine that takes more
# than a path: f ($path, { name => value, ... }). Returns the hash
# reference, or sets @ERROR and returns undef if there are arguments
# after the hash, a name the subroutine does not take (a misspelling
# would otherwise be silently ignored), or a required name missing or
# undef.
sub _named_args {
    my ($sub, $argv, $required, $optional) = @_;
    my $arg = $argv->[1];
    if (@$argv != 2) {
	@ERROR = ("$sub: named form takes a path and one hash reference, nothing more\n");
	return undef;
    }
    my %known = map { $_ => 1 } (@$required, @$optional);
    my @unknown = sort (grep { !$known{$_} } keys %$arg);
    if (@unknown) {
	@ERROR = ("$sub: unknown argument(s): @unknown\n");
	return undef;
    }
    my @missing = grep { !defined ($arg->{$_}) } @$required;
    if (@missing) {
	@ERROR = ("$sub: missing required argument(s): @missing\n");
	return undef;
    }
    return $arg;
}

# Write the passphrase to a signify pipe opened with '|-' and close it.
# SIGPIPE is ignored only here, after the fork inside open, so signify
# itself keeps the default disposition; a signify that exits before
# reading (bad key path, etc.) is then a write error, not a signal that
# kills the caller. Returns true if signify exited 0; $? holds its status.
sub _send_passphrase_and_close {
    my ($fh, $passphrase) = @_;
    local $SIG{PIPE} = 'IGNORE';
    # syswrite, not print: a buffered print is only written when close
    # flushes it, and if that flush fails with EPIPE (signify, using a
    # key made with -n, exited without reading) Perl's close returns
    # with $? = -1 instead of signify's status, so a successful signing
    # was reported as "signify failed could not be run". An unbuffered
    # write fails (harmlessly) here, and close has nothing to flush.
    syswrite ($fh, "$passphrase\n");
    # close waits for signify and sets $? to its status. close's own
    # return value is not used: it is false whenever $? is non-zero.
    close ($fh);
    return ($? == 0);
}

# Describe a wait status for an error message.
sub _describe_status {
    my ($status) = @_;
    return 'could not be run' if ($status == -1);
    return 'killed by signal ' . ($status & 127) if ($status & 127);
    return 'exit ' . ($status >> 8);
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
	$skip_signify_check, $skip_prechecks);
    if (ref ($_[1]) eq 'HASH') {
	my $arg = _named_args ('verify', \@_, ['public_key_path'],
			       ['skip_signify_check', 'skip_prechecks'])
	    or return undef;
	$file_path = $_[0];
	($public_key_path, $skip_signify_check, $skip_prechecks) =
	    @{$arg}{qw(public_key_path skip_signify_check skip_prechecks)};
    }
    else { # positional form (deprecated)
	($file_path, $public_key_path,
	 $skip_signify_check, $skip_prechecks) = @_;
    }

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
# and a temp dir. Optionally skip signify check and file prechecks.
# As of 1.3 $temp_dir is not used (kept so callers need not change): the
# signed output is written to a temp file in the gzip's own directory,
# given the original's mode and owner, and renamed over the original, so
# the original is either replaced whole or left untouched. The caller
# therefore needs create access to the gzip's directory. If $gzip_path
# is a symlink, the file it points to is replaced (one level of link
# only), as copy() did before.
# Possible errors:
# Pre-signify errors:
# no executable $SIGNIFY_PATH. $!
# no readable secret key $secret_key_path. $!
# no readable gzip $gzip_path. $!
# no writeable gzip $gzip_path. $!
# cannot read symlink $gzip_path. $!
# cannot stat gzip $target. $!
# gzip $target is not a regular file
# cannot create temp file in $gzip_dir. $!
# Post-signify errors:
# failed to sign gzip $gzip_path. $!
# failed to sign gzip $gzip_path: signify (exit N|killed by signal N|could not be run)
# error signing gzip $gzip_path. Zero-length output.
# cannot set mode|owner of signed gzip for $gzip_path. $!
# failed to replace $gzip_path with signed gzip. $!
sub sign_gzip {
    my ($gzip_path, $signify_passphrase, $secret_key_path, $temp_dir,
	$skip_signify_check, $skip_prechecks);
    if (ref ($_[1]) eq 'HASH') {
	# No temp_dir: the named form does not take the unused argument.
	my $arg = _named_args ('sign_gzip', \@_, ['secret_key_path'],
			       ['passphrase', 'skip_signify_check', 'skip_prechecks'])
	    or return undef;
	$gzip_path = $_[0];
	($signify_passphrase, $secret_key_path,
	 $skip_signify_check, $skip_prechecks) =
	    @{$arg}{qw(passphrase secret_key_path skip_signify_check skip_prechecks)};
	$signify_passphrase //= '';
    }
    else { # positional form (deprecated); $temp_dir is ignored
	($gzip_path, $signify_passphrase, $secret_key_path, $temp_dir,
	 $skip_signify_check, $skip_prechecks) = @_;
    }
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

    # Renaming over a symlink would replace the link, not the file it
    # points to (which is what copy() used to write). So follow one level
    # of link, as 1.2a's copy did, and replace the target. A link to a
    # link, or to anything but a regular file, is refused.
    my $target = $gzip_path;
    if (-l $target) {
	my $link = readlink ($target);
	if (!defined ($link)) {
	    @ERROR = ("cannot read symlink $gzip_path. $!\n");
	    return undef;
	}
	$target = ($link =~ m{^/}) ? $link : dirname ($target) . "/$link";
    }

    # The original's mode and owner, to give the replacement.
    my @st = lstat ($target);
    if (!@st) {
	@ERROR = ("cannot stat gzip $target. $!\n");
	return undef;
    }
    if (!-f _) {
	@ERROR = ("gzip $target is not a regular file\n");
	return undef;
    }

    # Random filename beside the original, so the final rename is atomic
    # and never crosses a filesystem. A dot name without a .tgz suffix,
    # so a leftover (if the caller is killed) is not taken for a package.
    my $gzip_dir = dirname ($target);
    eval {
	($tempfh, $temp_file) = tempfile ('.signify.XXXXXXXX', DIR => $gzip_dir, UNLINK => 0);
    };
    if ($@ || !defined ($temp_file)) {
	@ERROR = ("cannot create temp file in $gzip_dir. $!\n");
	return undef;
    }
    close ($tempfh);

    # Sign the gzip.
    my $signifypipe_fh;
    if (!open ($signifypipe_fh, '|-', $SIGNIFY_PATH, '-Sz', '-s', $secret_key_path, '-m', $target, '-x', $temp_file)) {
	@ERROR = ("failed to sign gzip $gzip_path. $!\n");
	unlink ($temp_file);
	return undef;
    }
    if (!_send_passphrase_and_close ($signifypipe_fh, $signify_passphrase)) {
	@ERROR = ("failed to sign gzip $gzip_path: signify " . _describe_status ($?) . "\n");
	unlink ($temp_file);
	return undef;
    }

    # If zero-length, return error and don't overwrite original.
    if (!-s $temp_file) {
	@ERROR = ("error signing gzip $gzip_path. Zero-length output.\n");
	unlink ($temp_file);
	return undef;
    }

    # Give the signed file the original's mode and owner. The temp file
    # was created 0600 and owned by this process.
    if (!chmod ($st[2] & 07777, $temp_file)) {
	@ERROR = ("cannot set mode of signed gzip for $gzip_path. $!\n");
	unlink ($temp_file);
	return undef;
    }
    my @tst = stat ($temp_file);
    if (@tst && ($tst[4] != $st[4] || $tst[5] != $st[5])) {
	if (!chown ($st[4], $st[5], $temp_file)) {
	    @ERROR = ("cannot set owner of signed gzip for $gzip_path. $!\n");
	    unlink ($temp_file);
	    return undef;
	}
	# chown can clear setuid/setgid bits; restore the mode.
	chmod ($st[2] & 07777, $temp_file);
    }

    # Replace the original in one step.
    if (!rename ($temp_file, $target)) {
	@ERROR = ("failed to replace $gzip_path with signed gzip. $!\n");
	unlink ($temp_file);
	return undef;
    }

    return 1;
}

# Return the signer key name from a gzip header without streaming or
# verifying the file. Used to check which key was used for signing
# before deciding whether to call verify_gzip, avoiding an unnecessary
# full stream of the file if the key is not acceptable.
# Returns the signer secret key path (or basename) from the gzip header,
# or undef if the header cannot be read or has no key field.
sub get_gzip_signer {
    my ($gzip_path) = @_;
    my ($signer, $signdate, $comment, $errmsg) = _gzip_get_header ($gzip_path);
    return $signer;
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
	$skip_signify_check, $skip_prechecks);
    if (ref ($_[1]) eq 'HASH') {
	my $arg = _named_args ('verify_gzip', \@_, ['temp_dir'],
			       ['require_public_key_file', 'require_secret_key_path',
				'skip_signify_check', 'skip_prechecks'])
	    or return undef;
	$gzip_path = $_[0];
	($temp_dir, $require_public_key_file, $require_secret_key_path,
	 $skip_signify_check, $skip_prechecks) =
	    @{$arg}{qw(temp_dir require_public_key_file require_secret_key_path
		       skip_signify_check skip_prechecks)};
    }
    else { # positional form (deprecated)
	($gzip_path, $temp_dir,
	 $require_public_key_file, $require_secret_key_path,
	 $skip_signify_check, $skip_prechecks) = @_;
    }
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
		@ERROR = ("mismatch of required public key and secret key filenames.\n");
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
		@ERROR = ("gzip header: mismatch of public key and secret key filenames.\n");
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
#    "no exec of signify" (if child exec of signify fails; the child's
#       own message, "Could not exec ...", is returned instead when it
#       reached the temp file)
#    "no key name in gzip header" (comment has no usable key= line)
#    "signify killed by signal N" (crashed or killed; never verified)
#    any other text signify wrote to stderr, unchanged but chomped
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

    if (defined ($errmsg)) {
	return ($verified, $errmsg);
    }

    # The header must name a key. basename strips any directory; a name
    # that is empty or a directory reference would otherwise make
    # "$SIGNIFY_KEY_DIR/$signer_pubkey" the key directory itself, which
    # passes the -e test below.
    if (defined ($signer)) {
	$signer_pubkey = $signer;
	$signer_pubkey =~ s/\.sec\z/.pub/;
	$signer_pubkey = basename ($signer_pubkey);
    }
    if (!defined ($signer_pubkey) || $signer_pubkey eq '' ||
	$signer_pubkey eq '.' || $signer_pubkey eq '..') {
	return ($verified, 'no key name in gzip header', $signer, $signdate);
    }

    if (!-e "$SIGNIFY_KEY_DIR/$signer_pubkey") {
	$errmsg = "no public key $signer_pubkey";
	return ($verified, $errmsg, $signer, $signdate);
    }

    # Open the gzip before forking, so a failure here leaves no child
    # waiting on the pipe.
    open (my $gzfh, '<', $file) or
	return ($verified, "could not open gzip $file. $!", $signer, $signdate);
    binmode ($gzfh);

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

	# signify exits as soon as the signature or a block hash fails,
	# usually with much of the gzip still unsent. With SIGPIPE at its
	# default, the next write would kill the caller (no message, no
	# END blocks). Ignored here, in the parent only, after the fork,
	# the write fails instead and signify's status decides the result.
	local $SIG{PIPE} = 'IGNORE';

	# Send gzip to child.
	# using perl i/o instead of sysread
	# if there are opportunities to improve efficiency they might
	# be here, this is slow (with both read and sysread).
	while (read ($gzfh, my $buf, $buffsize)) {
	    print $writefh $buf or last;
	}
	close ($gzfh);
	close ($writefh); # may fail with EPIPE; signify's status decides

	my $waited = waitpid ($pid, 0);
	my $status = ($waited == $pid) ? $? : -1;

	# Child's error output.
	my $child_err = '';
	if (open (my $errfile, '<', $temp_file)) {
	    $errfile_opened = 1;
	    $child_err = do { local $/; <$errfile> } // '';
	    close ($errfile);
	}
	unlink ($temp_file);
	chomp ($child_err);

	# Verified only if signify ran to completion, exited 0 and said
	# nothing. A signal (crash, kill) or a failed wait is not verified
	# even when stderr is empty: $? >> 8 is 0 in both cases.
	if ($status == -1) {
	    $errmsg = 'no exec of signify: could not wait for it';
	}
	elsif ($status & 127) {
	    $errmsg = 'signify killed by signal ' . ($status & 127);
	    $errmsg .= ": $child_err" if ($child_err ne '');
	}
	elsif ($child_err ne '') {
	    # Messages are prefixed with the program name, which is
	    # signify-openbsd on Linux, so match from the colon.
	    if ($child_err =~ /: unsigned gzip archive/) {
		$errmsg = 'unsigned gzip archive';
	    }
	    elsif ($child_err =~ /: invalid magic in gzheader/) {
		$errmsg = 'not a gzip';
	    }
	    elsif ($child_err =~ /: gzheader truncated/) {
		$errmsg = 'gzheader truncated';
	    }
	    elsif ($child_err =~ /: signature mismatch/) {
		$errmsg = 'signature mismatch';
	    }
	    else {
		$errmsg = $child_err;
	    }
	}
	else {
	    my $child_exit_status = $status >> 8;
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
	    elsif (!$errfile_opened) {
		# signify exited 0, but its stderr could not be read, so a
		# message it may have printed is unknown. signify's exit
		# status is authoritative for verification.
		$verified = 1;
	    }
	    else { # exit 0 and no message
		$verified = 1;
	    }
	}
	return ($verified, $errmsg, $signer, $signdate);
    }
    else { # child
	# This is a copy of the caller. It must never return into the
	# caller's code or run its END blocks, so every failure leaves
	# with POSIX::_exit, after writing the reason with syswrite
	# (unbuffered: _exit does not flush). Exit 2 is reported by the
	# parent as "no exec of signify" if no message reached the temp
	# file.
	close ($writefh);
	close ($gzfh);
	# Open STDIN from read side of pipe and close readfh.
	if (!open (STDIN, '<&', $readfh)) {
	    syswrite (STDERR, "dup2 failed: $!\n");
	    POSIX::_exit (2);
	}
	close ($readfh);
	# Send STDERR to temp file for retrieval by parent.
	POSIX::_exit (2) if (!open (STDERR, '>', $temp_file));
	# Send STDOUT to /dev/null.
	if (!open (STDOUT, '>', '/dev/null')) {
	    syswrite (STDERR, "Could not open /dev/null. $!\n");
	    POSIX::_exit (2);
	}
	# Run signify on the gzip file stream.
	{
	    no warnings 'exec';
	    exec ($SIGNIFY_PATH, '-zV', '-p', "$SIGNIFY_KEY_DIR/$signer_pubkey");
	}
	syswrite (STDERR, "Could not exec $SIGNIFY_PATH. $!\n");
	POSIX::_exit (2);
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

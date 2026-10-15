# Signify.pm

A Perl module wrapping OpenBSD's `signify` tool for cryptographically signing
and verifying files. Supports detached signatures for individual files and
embedded signatures in gzipped tar archives (the format used by OpenBSD
packages). Intended for use in Perl scripts that need to sign or verify files
as part of a larger workflow.

Used by [distribute/install](https://github.com/lippard661/distribute) to
sign distributed files and verify signatures before installation, by
[reportnew](https://github.com/lippard661/reportnew) to verify signed execute
scripts, and by [sigtree](https://github.com/lippard661/sigtree) to sign and
verify integrity spec files.

Works on OpenBSD (signify standard), Linux (signify-openbsd via apt), and
macOS (signify via Homebrew).

## Background: signify and gzip embedded signatures

OpenBSD's `signify` uses Ed25519 public-key signatures. It is the tool used
to sign and verify official OpenBSD releases and packages. Unlike PGP/GPG,
signify is intentionally minimal: one algorithm, simple key management, fast
verification.

A distinctive feature used by the OpenBSD package system is embedding a
signature in the gzip comment field of a `.tgz` archive. The signature covers
the entire archive content; the comment field records the signing key name and
date. This means a signed package is a single self-contained file — no
separate `.sig` file needed — and the signature can be verified before the
archive is extracted. Signify.pm supports both detached signatures (a separate
`.sig` file alongside the signed file) and this embedded gzip signature format.

## Installation

### Recommended: via install.pl

[install.pl](https://github.com/lippard661/distribute) installs Signify.pm
into the correct site Perl directory automatically on OpenBSD, Linux, and
macOS:

```
pkg_add ./Signify-<version>.tgz          # OpenBSD
install.pl                                # OpenBSD, Linux, or macOS via install.pl
```

The OpenBSD package is signed with signify. To verify:
```
signify -C -p discord.org-2026-pkg.pub -x Signify-<version>.tgz
```
Public key: https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

### Manual installation

Copy `Signify.pm` to your site Perl directory:
```sh
# OpenBSD
cp src/Signify.pm /usr/local/lib/perl5/site_perl/

# Linux (path may vary by distribution)
cp src/Signify.pm /usr/local/share/perl/<version>/

# macOS with Homebrew Perl
cp src/Signify.pm /opt/homebrew/lib/perl5/site_perl/
```

### Platform requirements

- **OpenBSD**: signify at `/usr/bin/signify` (standard)
- **Linux**: `apt install signify-openbsd`; installed at `/usr/bin/signify-openbsd`
- **macOS**: `brew install signify-osx`; installed at `/opt/homebrew/bin/signify`
  (Apple Silicon). On Intel Macs, Homebrew installs to `/usr/local/bin/signify`;
  set `$Signify::SIGNIFY_PATH` accordingly if needed.

### Perl module dependencies

Requires Perl 5.10 or later.

Standard modules (included with Perl): `strict`, `warnings`, `Exporter`,
`File::Basename`, `File::Temp`, `IPC::Open3`, `POSIX`

Non-standard: none required on OpenBSD, Debian Linux, or macOS —
`IO::Uncompress::Gunzip` (part of IO::Compress) is included by default
on all three. If using another platform it may need to be installed via CPAN.

### pledge/unveil requirements (OpenBSD)

If your script uses OpenBSD::Pledge and OpenBSD::Unveil, these are the
accesses Signify.pm's own Perl code makes (signify itself runs after exec):

```
pledge: stdio rpath proc exec
        wpath cpath     verify_gzip (temp file in temp_dir),
                        sign_gzip (temp file beside the gzip, renamed over it)
        fattr           sign_gzip (sets the original's mode on the new file)
        chown           sign_gzip, only when running as root on a gzip
                        owned by another user or group
        unveil          if your script calls unveil after loading Signify

unveil: /usr/bin/signify rx      rx, not x: it is tested with -x unless
                                 skip_signify_check is set
        verify_gzip:  /etc/signify r (always, prechecks or not),
                      the gzip r, temp_dir rwc
        sign_gzip:    the gzip's directory rwc, secret key r
        sign:         the file r, the file's directory rwc, secret key r
        verify:       the file r, the .sig file r, public key r
```

`/dev/null` needs no unveil; the kernel lets it bypass unveil.

Your script does not need to set `$SIG{PIPE}`. Signify.pm ignores SIGPIPE
itself, only while it writes to signify, so a signify that exits early (for
example on a tampered package) is reported as a failure instead of killing
your script.

## API

No symbols are exported by default. Import what you need:

```perl
use Signify qw(get_gzip_signer sign verify sign_gzip verify_gzip signify_error);
```

Or access via full package name:
```perl
Signify::sign(...);
```

All functions return `undef` on error. Call `signify_error()` to retrieve
error messages after a failure.

### Calling conventions

As of 1.3, `sign`, `verify`, `sign_gzip` and `verify_gzip` take named
arguments: the path, then a hash reference.

```perl
verify_gzip($gzip_path, { temp_dir => '/tmp', require_public_key_file => 'mykey.pub' });
```

In the named form, a misspelled or unknown argument name, a missing required
argument, or anything after the hash reference is an error: the call returns
`undef` and `signify_error()` says which.

The older positional form (shown under each function as *Deprecated*)
still works. It is recognized by a second argument that is not a hash
reference. It will be removed in a later release, so new code should use
the named form.

---

### sign

```perl
my $result = sign($file_path, { secret_key_path    => $secret_key_path,
                                passphrase         => $passphrase,
                                skip_signify_check => 0,
                                skip_prechecks     => 0 });
```

Signs `$file_path` with the given secret key, creating a detached signature
file at `$file_path.sig`. The passphrase is passed to signify on stdin.

Returns 1 on success, undef on error, including when signify fails (for
example on a wrong passphrase). signify's own message goes to the terminal
and is not captured in `signify_error()`, which reports the exit status.

**Arguments**:
- `secret_key_path` — path to signify secret key (`.sec` file) (required)
- `passphrase` — passphrase for the secret key (optional; defaults to the
  empty string, for a key made with `signify -G -n`)
- `skip_signify_check` — skip check that signify binary exists (optional)
- `skip_prechecks` — skip checks for file/key readability (optional)

*Deprecated positional form:*
`sign($file_path, $passphrase, $secret_key_path, $skip_signify_check, $skip_prechecks)`

---

### verify

```perl
my $result = verify($file_path, { public_key_path    => $public_key_path,
                                  skip_signify_check => 0,
                                  skip_prechecks     => 0 });
```

Verifies the detached signature at `$file_path.sig` against `$file_path`
using the given public key.

Returns 1 on success (signature verified), undef on error or verification
failure.

**Arguments**:
- `public_key_path` — path to signify public key (`.pub` file) (required)
- `skip_signify_check` — skip check that signify binary exists (optional)
- `skip_prechecks` — skip checks for file/key/signature readability (optional)

*Deprecated positional form:*
`verify($file_path, $public_key_path, $skip_signify_check, $skip_prechecks)`

---

### sign_gzip

```perl
my $result = sign_gzip($gzip_path, { secret_key_path    => $secret_key_path,
                                     passphrase         => $passphrase,
                                     skip_signify_check => 0,
                                     skip_prechecks     => 0 });
```

Signs a gzipped tar archive in place, embedding the signature in the gzip
comment field.

The signed output is written to a temporary file (`.signify.XXXXXXXX`) in the
same directory as the archive. That file is given the original's mode and
owner and then renamed over the original. The original is therefore either
replaced whole or left untouched: a signify failure, zero-length output, or
a full disk leaves it unchanged, and the temporary file is removed. If
`$gzip_path` is a symlink, the file it points to is replaced (one level of
link only).

Your script needs create access to the archive's directory (see
pledge/unveil above).

Returns 1 on success, undef on error.

**Arguments**:
- `secret_key_path` — path to signify secret key (required)
- `passphrase` — passphrase for the secret key (optional; defaults to the
  empty string)
- `skip_signify_check` — skip check that signify binary exists (optional)
- `skip_prechecks` — skip checks for file/key readability (optional)

The named form does not accept `temp_dir`.

*Deprecated positional form:*
`sign_gzip($gzip_path, $passphrase, $secret_key_path, $temp_dir, $skip_signify_check, $skip_prechecks)`.
`$temp_dir` is ignored as of 1.3 but must still be passed, so that the
arguments after it stay in place.

---

### get_gzip_signer

```perl
my $signer = get_gzip_signer($gzip_path);
```

Returns the signing key name recorded in the archive's gzip header (the
`key=` line, normally the secret key's file name), or undef if the header
cannot be read or has no key line. It reads only the header and does not
verify anything. Use it to decide whether to call `verify_gzip` without
streaming an archive signed with a key you would reject anyway.

**Parameters**:
- `$gzip_path` — path to `.tgz` file

---

### verify_gzip

```perl
my ($signer, $signdate) = verify_gzip($gzip_path,
                                      { temp_dir                => '/tmp',
                                        require_public_key_file => 'mykey.pub',
                                        require_secret_key_path => '/etc/signify/mykey.sec',
                                        skip_signify_check      => 0,
                                        skip_prechecks          => 0 });
```

Verifies the embedded signature in a gzipped tar archive. Reads the signing
key name and date from the gzip comment field, locates the corresponding
public key in `/etc/signify`, and verifies the signature by streaming the
archive through signify.

Returns `($signer, $signdate)` on success, undef on error or verification
failure.

The result is a pass only if signify ran to completion, exited 0 and printed
nothing. A signify that crashes or is killed by a signal is reported as
"signify killed by signal N", never as verified.

Optionally requires a specific public key file or secret key path, rejecting
archives signed with any other key.

**Arguments**:
- `temp_dir` — writable directory for a temporary file that holds
  signify's error output (required)
- `require_public_key_file` — require this specific public key filename (optional)
- `require_secret_key_path` — require this specific secret key path (optional)
- `skip_signify_check` — skip check that signify binary exists (optional)
- `skip_prechecks` — skip gzip header pre-checks (optional)

*Deprecated positional form:*
`verify_gzip($gzip_path, $temp_dir, $require_public_key_file, $require_secret_key_path, $skip_signify_check, $skip_prechecks)`

---

### signify_error

```perl
my @errors = signify_error();   # list context: array of error strings
my $error  = signify_error();   # scalar context: concatenated error string
```

Returns error messages from the most recent call. The `@ERROR` package
variable is reset at the start of each function call.

---

## Package variables

These can be set before calling functions if your environment differs from
the defaults:

```perl
$Signify::SIGNIFY_PATH    # path to signify binary (auto-detected by OS)
$Signify::SIGNIFY_KEY_DIR # primary key directory (default: /etc/signify)
$Signify::ALT_KEY_DIR     # fallback key directory (default: ./)
```

## Usage example

```perl
use Signify qw(sign verify sign_gzip verify_gzip signify_error);

# Sign a file with a detached signature
sign('/path/to/file', { secret_key_path => '/etc/signify/mykey.sec',
                        passphrase      => $passphrase })
    or die "Sign failed: " . signify_error();

# Verify a file against its detached signature
verify('/path/to/file', { public_key_path => '/etc/signify/mykey.pub' })
    or die "Verify failed: " . signify_error();

# Sign a package (embedded gzip signature)
sign_gzip('/path/to/package.tgz', { secret_key_path => '/etc/signify/mykey.sec',
                                    passphrase      => $passphrase })
    or die "Sign failed: " . signify_error();

# Verify a package, requiring a specific signing key
my ($signer, $date) = verify_gzip('/path/to/package.tgz',
                                  { temp_dir                => '/tmp',
                                    require_public_key_file => 'mykey.pub',
                                    require_secret_key_path => '/etc/signify/mykey.sec' })
    or die "Verify failed: " . signify_error();
print "Signed by $signer on $date\n";
```

## Security Notes

- Secret keys should be passphrase-protected and stored with mode 0600
- Public keys used for verification should be in `/etc/signify` or
  explicitly specified; key directories should be root-readable only
  since they reveal your signing infrastructure
- The `require_public_key_file` and `require_secret_key_path` arguments
  to `verify_gzip` should be used when the identity of the signing key
  matters, not just that some valid signature exists. Without them, an
  archive signed by any key whose public key is in `/etc/signify` verifies.
- Verification fails closed: a signify crash, a signal, an exec failure or
  any message from signify counts as not verified. If signify cannot be
  run, the forked child exits at once and never returns into your script's
  code or runs its `END` blocks.
- When using pledge/unveil, unveil the minimum necessary paths as documented
  above

## Related Tools

- [distribute](https://github.com/lippard661/distribute) — uses Signify.pm to sign distributed files and verify before installation
- [reportnew](https://github.com/lippard661/reportnew) — uses Signify.pm to verify signed execute scripts
- [sigtree](https://github.com/lippard661/sigtree) — uses Signify.pm to sign and verify integrity spec files
- [syslock](https://github.com/lippard661/syslock) — manages immutability of signify key directories

## Author

Jim Lippard  
https://www.discord.org/lippard/  
https://github.com/lippard661

## License

See individual files for license information.

## Changelog

See docs/ChangeLog for detailed modification history.

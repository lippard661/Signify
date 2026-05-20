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
- **macOS**: `brew install signify`; installed at `/opt/homebrew/bin/signify`
  (Apple Silicon). On Intel Macs, Homebrew installs to `/usr/local/bin/signify`;
  set `$Signify::SIGNIFY_PATH` accordingly if needed.

### Perl module dependencies

Standard modules (included with Perl): `strict`, `warnings`, `Exporter`,
`File::Basename`, `File::Copy`, `File::Temp`, `IPC::Open3`, `Symbol`

Non-standard: none required on OpenBSD, Debian Linux, or macOS —
`IO::Uncompress::Gunzip` (part of IO::Compress) is included by default
on all three. If using another platform it may need to be installed via CPAN.

### pledge/unveil requirements (OpenBSD)

If your script uses OpenBSD::Pledge and OpenBSD::Unveil, Signify.pm requires:
```
pledge: stdio rpath proc exec unveil
unveil: /usr/bin/signify rx
        pubkey r, file r, sigfile r    (if using prechecks)
        temp_dir rwc                   (for verify_gzip and sign_gzip)
        /dev/null rwc                  (for verify_gzip)
```

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

---

### sign

```perl
my $result = sign($file_path, $passphrase, $secret_key_path,
                  $skip_signify_check, $skip_prechecks);
```

Signs `$file_path` with the given secret key, creating a detached signature
file at `$file_path.sig`. The passphrase is passed to signify on stdin.

Returns 1 on success, undef on error.

**Parameters**:
- `$file_path` — path to file to sign
- `$passphrase` — passphrase for the secret key
- `$secret_key_path` — path to signify secret key (`.sec` file)
- `$skip_signify_check` — skip check that signify binary exists (optional)
- `$skip_prechecks` — skip checks for file/key readability (optional)

---

### verify

```perl
my $result = verify($file_path, $public_key_path,
                    $skip_signify_check, $skip_prechecks);
```

Verifies the detached signature at `$file_path.sig` against `$file_path`
using the given public key.

Returns 1 on success (signature verified), undef on error or verification
failure.

**Parameters**:
- `$file_path` — path to file to verify
- `$public_key_path` — path to signify public key (`.pub` file)
- `$skip_signify_check` — skip check that signify binary exists (optional)
- `$skip_prechecks` — skip checks for file/key/signature readability (optional)

---

### sign_gzip

```perl
my $result = sign_gzip($gzip_path, $passphrase, $secret_key_path, $temp_dir,
                       $skip_signify_check, $skip_prechecks);
```

Signs a gzipped tar archive in place, embedding the signature in the gzip
comment field. The original file is replaced with the signed version only if
signing succeeds and the copy of the signed output over the original succeeds;
zero-length output and copy failures are both treated as errors leaving the
original unchanged.

Returns 1 on success, undef on error.

**Parameters**:
- `$gzip_path` — path to `.tgz` file to sign
- `$passphrase` — passphrase for the secret key
- `$secret_key_path` — path to signify secret key
- `$temp_dir` — writable directory for temporary files during signing
- `$skip_signify_check` — skip check that signify binary exists (optional)
- `$skip_prechecks` — skip checks for file/key readability (optional)

---

### get_gzip_signer

```perl
my ($signer) = get_gzip_signer($gzip_path);
```

Obtains the signer from a gzip for use before verification.

**Parameters**:
- `$gzip_path` — path to `.tgz` file to verify

---

### verify_gzip

```perl
my ($signer, $signdate) = verify_gzip($gzip_path, $temp_dir,
                                       $require_public_key_file,
                                       $require_secret_key_path,
                                       $skip_signify_check, $skip_prechecks);
```

Verifies the embedded signature in a gzipped tar archive. Reads the signing
key name and date from the gzip comment field, locates the corresponding
public key in `/etc/signify`, and verifies the signature.

Returns `($signer, $signdate)` on success, undef on error or verification
failure.

Optionally requires a specific public key file or secret key path, rejecting
archives signed with any other key.

**Parameters**:
- `$gzip_path` — path to `.tgz` file to verify
- `$temp_dir` — writable directory for temporary files during verification
- `$require_public_key_file` — require this specific public key filename (optional)
- `$require_secret_key_path` — require this specific secret key path (optional)
- `$skip_signify_check` — skip check that signify binary exists (optional)
- `$skip_prechecks` — skip gzip header pre-checks (optional)

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
sign('/path/to/file', $passphrase, '/etc/signify/mykey.sec')
    or die "Sign failed: " . signify_error();

# Verify a file against its detached signature
verify('/path/to/file', '/etc/signify/mykey.pub')
    or die "Verify failed: " . signify_error();

# Sign a package (embedded gzip signature)
sign_gzip('/path/to/package.tgz', $passphrase, '/etc/signify/mykey.sec', '/tmp')
    or die "Sign failed: " . signify_error();

# Verify a package, requiring a specific signing key
my ($signer, $date) = verify_gzip('/path/to/package.tgz', '/tmp',
                                   'mykey.pub', '/etc/signify/mykey.sec')
    or die "Verify failed: " . signify_error();
print "Signed by $signer on $date\n";
```

## Security Notes

- Secret keys should be passphrase-protected and stored with mode 0600
- Public keys used for verification should be in `/etc/signify` or
  explicitly specified; key directories should be root-readable only
  since they reveal your signing infrastructure
- The `$require_public_key_file` and `$require_secret_key_path` parameters
  to `verify_gzip` should be used when the identity of the signing key
  matters, not just that some valid signature exists
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

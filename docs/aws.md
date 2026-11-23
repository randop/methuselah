# aws

## AWS CLI

`--macro=aws` is an AWS CLI [`credential_process`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)
helper. Credentials stay GPG-encrypted at rest and are handed over only after
the calling process has been verified as a genuine AWS CLI v2.

## Installation

Run the installer from the repository root as the account that will use the
CLI. It supports Linux on x86_64 and aarch64, and it refuses to run as root
or as the `methuselah` user:

```bash
./scripts/aws.sh
```

It creates the unprivileged `methuselah` system user (and the `users` group,
when that group is missing), installs the official AWS CLI v2 bundle under
`/opt/methuselah/aws-cli` owned by `methuselah:users` with mode 0750, and
links `/usr/local/bin/aws` and `/usr/local/bin/aws_completer`.
`/opt/methuselah` stays root-owned and mode 0755. The script writes the
root-owned `/etc/methuselah/aws-cli.sha256` pin, uses `sudo` for system
changes, and adds your account to `users`. Sign out and back in after the
first run so your shell picks up that group, then check `aws --version`.
Run the script again to update an existing install and refresh the pin.

**1. Encrypt the credentials** (type or paste, then press Ctrl-D; nothing goes
through shell history):

```bash
mkdir -p -m 700 ~/.aws
gpg --encrypt --recipient YOUR_KEY_ID --output ~/.aws/prod.credentials.gpg
chmod 600 ~/.aws/prod.credentials.gpg
```

```ini
access_key_id=AKIA...
secret_access_key=...
# temporary credentials only; a session_token requires an expiration
session_token=...
expiration=2027-11-22T18:00:00Z
```

The encrypted file must be a regular file that you own, with no group or
other write access. Its final path component must be the file itself; a
symlink is refused. `~` and `$HOME` in this path, and in the config below,
expand to your account's home from the password database.

Lines are `key=value`. Blank lines and `#` comments are skipped. The accepted
names are `access_key_id`, `secret_access_key`, `session_token`, and
`expiration`, in any case. `_` and `-` are ignored, and an `aws` prefix is
optional, so the `~/.aws/credentials` spellings (`aws_access_key_id` and the
rest) work. Unknown keys and duplicates are rejected.

`access_key_id` is 16 to 128 characters from `A–Z` and `0–9`.
`secret_access_key` is 20 to 128 characters from `A–Z`, `a–z`, `0–9`, `+`,
`/`, and `=`. `session_token`, when present, is 16 to 4096 characters from
that set plus `_`, `-`, and `.`, and it requires `expiration`. `expiration`
is UTC `YYYY-MM-DDTHH:MM:SSZ` and must still be in the future when the file
is decrypted. Error text never includes those values.

**2. Map the profile** in `~/.config/pinentry.methuselah`:

```ini
[aws:prod]
gpgfile=~/.aws/prod.credentials.gpg
```

The argument after `--macro=aws` selects `[aws:<profile>]`. The section name
is matched without regard to case. With no argument the profile is
`default`. A profile name is 1 to 64 characters from letters, digits, `_`,
`-`, `.`, and `@`.

**3. Point the CLI at the helper.** Have an administrator create
`/etc/methuselah/aws-home/.aws/config` with root ownership and no group or
other write access on the file or its directories. The CLI's `HOME`, the
`.aws` directory, and both `.aws/config` and `.aws/credentials` (when those
files exist) all have to meet that rule. A missing `.aws` directory is
allowed. Use the absolute path to the installed helper:

```ini
[profile prod]
credential_process = /usr/local/bin/methuselah --macro=aws prod
```

Run the CLI as your normal user with the root-controlled AWS home and the
GnuPG home that holds the private key for step 1:

```bash
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home aws --profile prod …
```

Set `GNUPGHOME` to the absolute path of your keyring directory if you keep it
elsewhere. The helper inherits it for GPGME decryption and still finds its
own configuration and encrypted file in your account's home directory. Keep
static keys out of the AWS home's `.aws/credentials` and leave plugin
configuration out of its `.aws/config`. Leave `LD_LIBRARY_PATH` unset: the
bundle copies an inherited value to `LD_LIBRARY_PATH_ORIG`, and the helper
refuses that variable.

Credentials are written only to a pipe or a socket, which is how
`credential_process` invokes the helper. A terminal or a regular file is
refused. Cancelling the passphrase prompt fails the request. Concurrent
calls wait for one another; if that lock cannot be taken, the request fails.

**4. Optional but recommended: pin the CLI binary.** The installer writes
`/etc/methuselah/aws-cli.sha256`. While that file exists, the running `aws`
image must match one of its digests. Remove the file only to skip the digest
check. A pin that is present but unusable fails closed: it must be a
root-owned regular file, not writable by group or others, in `sha256sum`
form, with at least one 64-digit hex digest, and at most 64 KiB. `#`
comments and blank lines are allowed. The text after each digest is ignored.

Refresh the pin after every manual AWS CLI update. Hash the file the process
executes, then keep the pin root-owned:

```bash
sudo install -d -o root -g root -m 755 /etc/methuselah
sha256sum "$(readlink -f /usr/local/bin/aws)" |
  sudo tee /etc/methuselah/aws-cli.sha256
sudo chown root:root /etc/methuselah/aws-cli.sha256
sudo chmod 0644 /etc/methuselah/aws-cli.sha256
```

### What is verified

The helper writes no credentials, and exits non-zero, unless the caller:

- is the native AWS CLI v2 executable at
  `/opt/methuselah/aws-cli/v2/current/dist/aws`,
  `/usr/local/aws-cli/v2/current/dist/aws`, `/usr/local/bin/aws`, or
  `/usr/bin/aws`. After symlinks are resolved the file name is `aws`. Every
  path component is owned by root or the `methuselah` service account and is
  not writable by group or others. The running image is matched by inode
  against `/proc/<pid>/exe`, so a copy, a rename, or a binary replaced on
  disk fails;
- shares the helper's root and mount namespace;
- matches a pinned SHA-256 when `/etc/methuselah/aws-cli.sha256` exists, as
  described above;
- reports no attached tracer when the helper reads the caller's `TracerPid`;
- was not started with `--endpoint-url`, `--ca-bundle`, `--no-verify-ssl`,
  `--debug`, or `--cli-auto-prompt`. A prefix of those options is refused
  too, such as `--endpoint` or `--no-verify`. `--cli-auto-prompt` is refused
  wherever it appears, including after `--`. A positional
  `export-credentials` is refused. After `--` that word is data, unless it
  is still the `configure` subcommand (`aws configure -- export-credentials`).
  `--no-cli-auto-prompt` is allowed;
- was not started with loader or interpreter overrides: `LD_*`, `PYTHON*`,
  `MALLOC_*`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, or `HOSTALIASES`. The
  official bundle at the first two paths above may set `LD_LIBRARY_PATH` to
  exactly its own executable directory, once, with no extra entries. A
  second `LD_LIBRARY_PATH`, and `LD_LIBRARY_PATH_ORIG`, are refused;
- was not started with endpoint, model, or trust-store overrides:
  `AWS_ENDPOINT_URL*`, `AWS_DATA_PATH`, `AWS_CA_BUNDLE`, `AWS_CONFIG_FILE`,
  `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONTAINER_CREDENTIALS_FULL_URI`,
  `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, or
  `SSLKEYLOGFILE`;
- uses a root-controlled `HOME`, set once and non-empty. When `.aws/config`
  or `.aws/credentials` is present, that file is root-controlled too.
  `config` has no `[plugins]` section. Neither file sets `cli_auto_prompt`
  to anything other than `off`, in any profile, including `[default]`.
  `AWS_CLI_AUTO_PROMPT` must be unset or `off`;
- maps only executable files owned by root or the `methuselah` account,
  through paths with the same ownership rules, apart from libffi's
  `/memfd:libffi` trampoline. Other deleted mappings are refused.

The tracer check is a snapshot and does not prevent a later attachment.

The caller is verified before the passphrase prompt. After the prompt the
helper checks that the parent is still that caller, verifies it again, and
writes nothing if a signal arrived in between.

### Limitations

- Only AWS CLI v2 is accepted. An installation owned by the account running
  the helper is refused, including a copy under that account's home. Root
  and the dedicated `methuselah` service account may own the installation.
  The account that runs the helper needs read and execute access through the
  `users` group.
- The pin covers the `aws` executable. Ownership and memory-map checks cover
  the rest of the install directory.
- The `methuselah` account can replace its own AWS CLI files. That is the
  trust delegated to the service account. The root-owned pin detects a
  changed executable until the pin is refreshed.
- Environment and arguments are what the CLI was started with, which is what
  the kernel reports in `/proc`. Linux only. A caller in another mount
  namespace, or with a different root, cannot be verified.
- An AWS CLI you trust can still use the credentials as the commands you give
  it direct. This helper decides who receives them, not what that CLI does.

# aws

## AWS CLI

`--macro=aws` is an AWS CLI [`credential_process`](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-sourcing-external.html)
helper. Credentials stay GPG-encrypted at rest and are handed over only after
the calling process has been verified as a genuine AWS CLI v2.

## Installation

Run the installer from the repository root as your normal user:

```bash
./scripts/aws.sh
```

It creates the unprivileged `methuselah` system user, installs AWS CLI v2 under
`/opt/methuselah/aws-cli` owned by `methuselah:users` with mode 0750, links
`/usr/local/bin/aws`, and writes the root-owned
`/etc/methuselah/aws-cli.sha256` pin. The script uses `sudo` for system changes.
Sign out and back in after the first run so your shell picks up the `users`
group, then check `aws --version`.

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
expiration=2026-11-22T18:00:00Z
```

**2. Map the profile** in `~/.config/pinentry.methuselah`:

```ini
[aws:prod]
gpgfile=~/.aws/prod.credentials.gpg
```

**3. Point the CLI at the helper.** Have an administrator create
`/etc/methuselah/aws-home/.aws/config` with root ownership and no group or
other write access on the file or its directories. Use the absolute path to
the installed helper:

```ini
[profile prod]
credential_process = /usr/local/bin/methuselah --macro=aws prod
```

Run the CLI as your normal user with that directory as its home:
`HOME=/etc/methuselah/aws-home aws --profile prod …`. Keep static keys out of
that home's `.aws/credentials` and leave all plugin configuration out of
its `.aws/config`. The helper still finds its own configuration and encrypted
file in your account's home directory.

**4. Optional but recommended: pin the CLI binary.** Pinning detects an
`aws` that was modified in place. The install script writes this pin for you;
refresh it after every manual AWS CLI update.

```bash
sudo install -d -m 755 /etc/methuselah
sha256sum "$(readlink -f /usr/local/bin/aws)" | sudo tee /etc/methuselah/aws-cli.sha256
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:6a3cb1f5030667c7ab6e8ffa5546c1990201e6fdac418bc66f1a7da96a4c464d -->

### What is verified

The helper prints nothing and exits non-zero unless the caller:

- is the native AWS CLI v2 executable at
  `/opt/methuselah/aws-cli/v2/current/dist/aws`,
  `/usr/local/aws-cli/v2/current/dist/aws`, `/usr/local/bin/aws`, or
  `/usr/bin/aws`, reached through path components owned by root or the
  `methuselah` service account and not writable by group or others, and
  matched by inode against the running process (copies, renamed or replaced
  binaries fail);
- matches a pinned SHA-256, when `/etc/methuselah/aws-cli.sha256` exists;
- has no tracer attached;
- was not started with `--endpoint-url`, `--ca-bundle`, `--no-verify-ssl`,
  `--debug`, `--cli-auto-prompt`, or `configure export-credentials`;
- was not started with loader overrides (the official Linux bundle's
  `LD_LIBRARY_PATH` is allowed only when it names its own trusted directory),
  `PYTHON*`, `MALLOC_*`, `AWS_ENDPOINT_URL*`,
  `AWS_CA_BUNDLE`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, or common
  CA-bundle (`SSL_CERT_*`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) variables;
- uses root-controlled `.aws/config` and `.aws/credentials` files, if present,
  with no `[plugins]` section in `config` and no auto-prompt setting other than
  `off` in either file; `AWS_CLI_AUTO_PROMPT` must also be unset or `off`;
- maps only trusted files as executable code, apart from libffi trampolines.


<!-- /coderabbit-ai-generated:v1 -->
The check runs before the passphrase prompt and again just before the
credentials are written.

### Limitations

- AWS CLI v1 (a Python script, e.g. Debian's `awscli`) is rejected on purpose.
  So are arbitrary user-owned installs such as `~/.local/aws-cli`: only
  root-owned installations and the dedicated `methuselah` service account are
  accepted. The account running the helper must not own the installation; it
  only needs read and execute access through the `users` group.
- The pin covers the `aws` launcher, not every file in its install directory;
  the ownership and memory-map checks cover those.
- The `methuselah` account can replace its own AWS CLI files. That is the trust
  delegated to the service account; the root-owned pin detects launcher changes
  unless it is refreshed.
- Environment and arguments are what the CLI was started with, which is what
  the kernel reports in `/proc`. Linux only.
- An AWS CLI you trust can still use the credentials as the commands you give
  it direct. This helper decides who receives them, not what that CLI does.

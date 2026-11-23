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

## Setup

The steps below use `gpg` directly. If you use `pass` and prefer to have the
AWS CLI write the profile entries, see
[Setup with `pass` and `aws configure`](#setup-with-pass-and-aws-configure)
for an alternative to steps 1–3.

### 1. Encrypt the credentials

Type or paste the credentials, then press Ctrl-D; nothing goes through shell
history:

```bash
mkdir -p -m 700 ~/.aws
gpg --encrypt --recipient YOUR_KEY_ID \
  --output ~/.aws/default.credentials.gpg
chmod 600 ~/.aws/default.credentials.gpg
```

Repeat this for every profile, replacing `default` in the file name. The
examples below also use `dev.credentials.gpg`, `stage.credentials.gpg`, and
`prod.credentials.gpg`.

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

### 2. Map profiles in Methuselah

Each AWS CLI profile that uses the helper needs an `[aws:…]` entry in
`~/.config/pinentry.methuselah`. Several AWS CLI profiles can point at the same
Methuselah profile if they share credentials:

```ini
[aws:default]
gpgfile=~/.aws/default.credentials.gpg

[aws:dev]
gpgfile=~/.aws/dev.credentials.gpg

[aws:stage]
gpgfile=~/.aws/stage.credentials.gpg

[aws:prod]
gpgfile=~/.aws/prod.credentials.gpg
```

Keep only the sections you need; the profile guides below use these names as
examples. The argument after `--macro=aws` selects `[aws:<profile>]`; with no
argument the profile is `default`. The section name is matched without regard
to case. A profile name is 1 to 64 characters from letters, digits, `_`, `-`,
`.`, and `@`. The name after `--macro=aws` is a Methuselah profile; it does not
have to match the AWS CLI profile name, but using the same name avoids
confusion.

### 3. Point the CLI at the helper

Have an administrator create `/etc/methuselah/aws-home/.aws/config` with root
ownership and no group or other write access on the file or its directories.
The CLI's `HOME`, the `.aws` directory, and both `.aws/config` and
`.aws/credentials` (when those files exist) all have to meet that rule. A
missing `.aws` directory is allowed. Your account also needs read access to
`config`; mode 0644 on the file and 0755 on the directories is enough. Keep
group and other write access off. Use the absolute path to the installed
helper in every `credential_process` entry.

All profiles can share the same root-controlled AWS home. Use `[default]` for
the default profile and `[profile <name>]` for each named profile; the same
file can hold both.

#### Default profile setup

Use this when commands run without `--profile` (or with `--profile default`).
If `AWS_PROFILE` or `AWS_DEFAULT_PROFILE` selects another profile, unset it or
pass `--profile default`. The helper receives no profile argument, so it reads
`[aws:default]`.

Add this to `/etc/methuselah/aws-home/.aws/config`:

```ini
[default]
credential_process = /usr/local/bin/methuselah --macro=aws
```

And this to `~/.config/pinentry.methuselah`:

```ini
[aws:default]
gpgfile=~/.aws/default.credentials.gpg
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:c15fb252e96033c049b48d9c08855fc99881c0554f7960ba8ffafa2db8871495 -->

Clear any exported AWS credentials before running the check so the CLI uses
the profile's credential helper:

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws sts get-caller-identity
```

<!-- /coderabbit-ai-generated:v1 -->

#### Single non-default profile setup

Use this when you always pass `--profile prod` or set `AWS_PROFILE=prod`. The
helper receives `prod`, so it reads `[aws:prod]`.

Add this to `/etc/methuselah/aws-home/.aws/config`:

```ini
[profile prod]
credential_process = /usr/local/bin/methuselah --macro=aws prod
```

And this to `~/.config/pinentry.methuselah`:

```ini
[aws:prod]
gpgfile=~/.aws/prod.credentials.gpg
```

Run:

```bash
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws --profile prod sts get-caller-identity
```

#### Multiple non-default profile setup

Add a `[profile …]` section to the root-controlled CLI config for each AWS CLI
profile. Each `credential_process` passes the Methuselah profile name to use;
profiles that share credentials can pass the same name.

Add this to `/etc/methuselah/aws-home/.aws/config`:

```ini
[profile dev]
credential_process = /usr/local/bin/methuselah --macro=aws dev

[profile stage]
credential_process = /usr/local/bin/methuselah --macro=aws stage

[profile prod]
credential_process = /usr/local/bin/methuselah --macro=aws prod
```

And this to `~/.config/pinentry.methuselah`:

```ini
[aws:dev]
gpgfile=~/.aws/dev.credentials.gpg

[aws:stage]
gpgfile=~/.aws/stage.credentials.gpg

[aws:prod]
gpgfile=~/.aws/prod.credentials.gpg
```

Run a command with the profile you want:

```bash
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws --profile dev sts get-caller-identity

GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws --profile stage sts get-caller-identity

GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws --profile prod sts get-caller-identity
```

`AWS_PROFILE=dev` is equivalent to `--profile dev`; `AWS_DEFAULT_PROFILE`
selects one when neither is set. With no profile selected, the CLI uses
`[default]`. Add `region = <your-region>` to a profile if its commands need a
region.

Select profiles with `--profile`, `AWS_PROFILE`, or `AWS_DEFAULT_PROFILE`, not
with `AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE`; the helper refuses a
CLI started with those overrides.

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

### 4. Optional but recommended: pin the CLI binary

The installer writes `/etc/methuselah/aws-cli.sha256`. While that file exists,
the running `aws` image must match one of its digests. Remove the file only to
skip the digest check. A pin that is present but unusable fails closed: it
must be a root-owned regular file, not writable by group or others, in
`sha256sum` form, with at least one 64-digit hex digest, and at most 64 KiB.
`#` comments and blank lines are allowed. The text after each digest is
ignored.

Refresh the pin after every manual AWS CLI update. Hash the file the process
executes, then keep the pin root-owned:

```bash
sudo install -d -o root -g root -m 755 /etc/methuselah
sha256sum "$(readlink -f /usr/local/bin/aws)" |
  sudo tee /etc/methuselah/aws-cli.sha256
sudo chown root:root /etc/methuselah/aws-cli.sha256
sudo chmod 0644 /etc/methuselah/aws-cli.sha256
```

## Setup with `pass` and `aws configure`

This alternative to steps 1–3 keeps the credential material in `pass` and
uses the AWS CLI to write the root-controlled profile entries. The
root-controlled AWS home from step 3 still applies, and so does the optional
pin in step 4. The helper never calls `pass`; it reads the `.gpg` file that
`pass` produced.

You need the AWS CLI from [Installation](#installation), `pass`, and a GPG
secret key available in the keyring that `pass` and the helper use. If `pass`
is not installed, use your package manager, for example `apt install pass` or
`dnf install pass`.

Do not run plain `aws configure` to enter access keys. It writes them in
plaintext to `.aws/credentials` in the selected home, outside the encrypted
store. Use `pass` for the secrets and `aws configure set` for the non-secret
settings such as `credential_process`, `region`, and `output`.

### Store credentials with pass

Initialize the store with the key that should decrypt the entries. Skip this
if the store is already initialized for the same key:

```bash
pass init YOUR_KEY_ID
```

`pass init` sets the recipients for the whole store; subdirectories can have
their own `.gpg-id`. If the store already exists, make sure your key is one
of the recipients before continuing. If the store already exists and you keep
a separate key per profile, initialize only the `aws` subdirectory with
`pass init --path aws YOUR_KEY_ID`.

Insert one entry per Methuselah profile. `--multiline` reads until Ctrl-D and
keeps the `key=value` lines together:

```bash
pass insert --multiline aws/default
pass insert --multiline aws/prod
```

Paste the `key=value` lines accepted in step 1. For temporary credentials,
include `session_token` and `expiration`. Use `--multiline`; a plain
`pass insert` stores a single line that the helper cannot parse.

The entries are stored as `~/.password-store/aws/default.gpg` and
`~/.password-store/aws/prod.gpg`, encrypted to the recipients in the
applicable `.gpg-id` (usually `~/.password-store/.gpg-id`). The helper
decrypts the file directly with GPGME, so `pass` does not have to be on
`PATH` when the CLI runs; GnuPG and `gpg-agent` are still required. Use the
same absolute `GNUPGHOME` for `pass` and for `aws`; if the keyring is
elsewhere, set it for both commands. The helper only needs a private key that
matches one recipient of the file.

`pass` creates a regular file that you own. Confirm that group and others
cannot write it, and clear that access if they can. Adjust the path if you
use `PASSWORD_STORE_DIR`, and repeat after `pass insert`, `pass edit`, or a
`pass init` that re-encrypts existing entries:

```bash
chmod 600 ~/.password-store/aws/*.gpg
```

If you use a different `PASSWORD_STORE_DIR`, point `gpgfile` at the absolute
path of the `.gpg` file there. The helper expands `~` from your account's
home in the password database, not from the AWS home it runs with. A
relative path is resolved against the helper's working directory, so use an
absolute path.

### Map the entries in Methuselah

Add one `[aws:…]` section per profile to `~/.config/pinentry.methuselah`
instead of the `~/.aws/*.credentials.gpg` paths from step 2, and point
`gpgfile` at the pass file:

```ini
[aws:default]
gpgfile=~/.password-store/aws/default.gpg

[aws:prod]
gpgfile=~/.password-store/aws/prod.gpg
```

Keep only the profiles you use. The part after `aws:` is the Methuselah
profile and follows the name rules in step 2. With no argument, the helper
uses `default`; otherwise it uses the name passed after `--macro=aws` in the
next section. The AWS CLI profile name does not have to match, but using the
same name avoids confusion.

### Write the CLI config with aws configure

Have an administrator create the root-controlled AWS home and write the
entries with `aws configure set`. `HOME` selects the AWS home, and
`--profile default` selects `[default]` even if `AWS_PROFILE` is set in the
administrator's environment. `aws configure` itself only prompts for access
keys, region, and output; it has no prompt for `credential_process`, so use
`aws configure set`:

```bash
sudo install -d -o root -g root -m 755 /etc/methuselah/aws-home
sudo env HOME=/etc/methuselah/aws-home \
  /usr/local/bin/aws configure set credential_process \
  '/usr/local/bin/methuselah --macro=aws' --profile default
```

For each named profile, pass the profile name to `aws configure set` and the
same name to the helper:

```bash
sudo env HOME=/etc/methuselah/aws-home \
  /usr/local/bin/aws configure set credential_process \
  '/usr/local/bin/methuselah --macro=aws prod' --profile prod
```

Repeat for `dev`, `stage`, and any other profile. `aws configure set` writes
`[default]` for `--profile default` and `[profile <name>]` otherwise,
creating the file if needed. Add `region` or `output` the same way:

```bash
sudo env HOME=/etc/methuselah/aws-home \
  /usr/local/bin/aws configure set region us-east-1 --profile prod
```

Make sure `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` are unset when
running these commands, or the CLI writes somewhere else. Afterward, make
sure the AWS home is root-owned, readable by your account, and not writable
by group or others:

```bash
sudo chown -R root:root /etc/methuselah/aws-home
sudo chmod -R go-w /etc/methuselah/aws-home
sudo chmod 755 /etc/methuselah/aws-home /etc/methuselah/aws-home/.aws
sudo chmod 644 /etc/methuselah/aws-home/.aws/config
sudo env HOME=/etc/methuselah/aws-home \
  /usr/local/bin/aws configure list-profiles
```

`aws configure list-profiles` should show `default` and each named profile.
Repeat the permission commands whenever you add a profile. `aws configure
set` writes only `config`; do not use it to set `aws_access_key_id` or
`aws_secret_access_key`, which would put plaintext secrets in
`.aws/credentials`.

### Update or remove entries

To rotate a secret, replace the entry with `pass edit aws/prod` or
`pass insert --multiline aws/prod`, then run the `chmod` above. No
Methuselah or AWS CLI config changes are needed because the path stays the
same. To remove a profile, delete the entry with `pass rm aws/prod` and
remove its `[aws:prod]` and `[profile prod]` sections.

### Verify

Run a command as your normal user, with the root-controlled AWS home and the
GPG home that holds the key used by `pass`. Make sure `AWS_CONFIG_FILE` and
`AWS_SHARED_CREDENTIALS_FILE` are unset; the helper refuses a CLI started
with either. Leave `LD_LIBRARY_PATH` unset too; the helper refuses an
inherited value.

```bash
pass ls aws
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws --profile default sts get-caller-identity

GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/aws-home \
  aws --profile prod sts get-caller-identity
```

`pass ls aws` confirms the entries exist. A successful command prints the
account, user, and ARN for the credential set.

### Troubleshooting

- `no [aws:<profile>] gpgfile`: add the matching `[aws:<profile>]` section to
  `~/.config/pinentry.methuselah`.
- `must be a regular file owned by you and not writable by group or others`:
  confirm that the file is not a symlink and run the `chmod` above.
- Credential decryption fails: confirm that a private key for one of the
  file's recipients is in the keyring named by `GNUPGHOME`.
- The AWS CLI refuses the environment: unset `AWS_CONFIG_FILE` and
  `AWS_SHARED_CREDENTIALS_FILE`, and leave `LD_LIBRARY_PATH` unset.

## What is verified

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

## Limitations

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

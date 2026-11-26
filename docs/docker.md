# docker

## Docker CLI

`--macro=docker` is a Docker [credential
helper](https://docs.docker.com/engine/reference/commandline/login/#credentials-store).
It is also selected when the program is invoked as
`docker-credential-methuselah`, which is how the Docker CLI calls helpers.
Credentials stay GPG-encrypted at rest and are handed over only after the
calling process has been verified as a genuine Docker CLI.

The helper is read-only. It answers `get` and `list`; `store` and `erase` are
refused, so `docker login` and `docker logout` cannot write through it. Edit
the encrypted file and its `[docker:…]` section instead.

## Installation

The Docker CLI must be installed by root in one of these locations:

- `/opt/methuselah/docker/docker`
- `/usr/local/bin/docker`
- `/usr/bin/docker`

After symlinks are resolved the executable must still be named `docker`. Every
path component and the executable must be owned by root or the `methuselah`
service account and must not be writable by group or others. A distribution
package that installs `/usr/bin/docker` as root satisfies this. A CLI installed
under your own home, and Docker Desktop's per-user setup, do not.

Install Methuselah itself as root and provide the helper name Docker looks
for:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/bin
sudo install -o root -g root -m 0755 .build/methuselah \
  /usr/local/bin/methuselah
sudo ln -sf /usr/local/bin/methuselah \
  /usr/local/bin/docker-credential-methuselah
```

`/usr/local/bin` must be on the `PATH` that the Docker CLI inherits. The helper
itself does not need to be named `docker`; the symlink is what Docker resolves
from the helper name `methuselah`.

For a root-managed static CLI under `/opt/methuselah`, verify the download
according to Docker's instructions, then install it as root:

```bash
sudo install -d -o root -g root -m 0755 /opt/methuselah/docker
sudo install -o root -g root -m 0755 /path/to/docker \
  /opt/methuselah/docker/docker
```

Do not run the Docker CLI through `sudo` to make the checks pass. The helper
runs as the user the Docker CLI runs as; running the CLI as root would make it
read root's Methuselah configuration and root's GPG keyring instead of yours.

## Setup

The steps below use `gpg` directly. The helper never calls `pass`, but it can
read a `.gpg` file that `pass` produced. Files written by `pass` are encrypted
but not signed, so they cannot satisfy the optional signer policy below.

### 1. Encrypt the credentials

Type or paste the credentials, then press Ctrl-D; nothing goes through shell
history:

```bash
mkdir -p -m 700 ~/.docker
gpg --encrypt --recipient YOUR_KEY_ID \
  --output ~/.docker/ghcr.credentials.gpg
chmod 600 ~/.docker/ghcr.credentials.gpg
```

Repeat this for every registry, replacing `ghcr` in the file name. The file
contains two `key=value` lines:

```ini
username=YOUR_USERNAME
password=YOUR_TOKEN
```

For `ghcr.io`, `password` is a personal access token with at least
`read:packages` (add `write:packages` to push). For Docker Hub, use your
account password or a personal access token. The helper returns both values
to the Docker CLI, which sends them to the registry as basic authentication.

Lines are `key=value`. Blank lines and `#` comments are skipped. The accepted
names are `username` and `password`, in any case. `_` and `-` are ignored, a
`docker` prefix is optional, and these aliases are accepted:

| Field | Aliases |
| --- | --- |
| `username` | `user`, `login`, `email` |
| `password` | `secret`, `token`, `identitytoken`, `identity` |

`username` is 1 to 256 characters and `password` is 1 to 4096 characters.
Values may contain printable ASCII, UTF-8 bytes, and tabs; other control
characters are rejected, and leading and trailing whitespace is trimmed.
Unknown keys, duplicate keys, and empty values are rejected. Error text never
includes the values.

The encrypted file must be a regular file that you own, with no group or other
write access. Its final path component must be the file itself; a symlink is
refused. `~` and `$HOME` in this path, and in the config below, expand to your
account's home from the password database, not to the overridden Docker
`HOME`.

### 2. Map servers in Methuselah

Each registry that uses the helper needs a `[docker:…]` entry in
`~/.config/pinentry.methuselah`:

```ini
[docker:ghcr.io]
gpgfile=~/.docker/ghcr.credentials.gpg

[docker:docker.io]
gpgfile=~/.docker/dockerhub.credentials.gpg
```

Keep only the sections you need. The section name is matched without regard
to case. For a registry address Docker sends to the helper, the lookup tries,
in order:

1. the address exactly as sent;
2. the address without `https://` or `http://`;
3. the address without trailing slashes;
4. the host alone.

So `[docker:ghcr.io]` covers both `ghcr.io` and
`https://ghcr.io/v2/`. The exact spelling, when present, wins over a
host-only section.

Docker Hub is sent as `https://index.docker.io/v1/`. One section using any of
`docker.io`, `index.docker.io`, `registry-1.docker.io`, or the full URL covers
all of its spellings. Use one of them, not several.

### 3. Configure the Docker CLI

The CLI reads `$HOME/.docker/config.json` before it invokes the helper. A
config file that your account can change could redirect `credHelpers` or
select another context, so the verifier requires `HOME`, its `.docker`
directory, and `.docker/config.json` to be root-controlled. Point the CLI at a
root-owned home:

```bash
sudo install -d -o root -g root -m 0755 \
  /etc/methuselah /etc/methuselah/docker-home
sudo install -d -o root -g root -m 0755 \
  /etc/methuselah/docker-home/.docker
sudo tee /etc/methuselah/docker-home/.docker/config.json >/dev/null <<'EOF'
{
  "credHelpers": {
    "ghcr.io": "methuselah",
    "https://index.docker.io/v1/": "methuselah"
  }
}
EOF
sudo chown root:root /etc/methuselah/docker-home/.docker/config.json
sudo chmod 0644 /etc/methuselah/docker-home/.docker/config.json
```

List only the registries you use. If the file already exists, merge these
entries into it instead of replacing it. `credHelpers` selects the helper per
registry. Alternatively, `{"credsStore": "methuselah"}` uses it for every
registry; a registry without a `[docker:…]` section then fails.

Run the CLI with the root-controlled home and your real GnuPG home:

```bash
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/docker-home \
  docker pull ghcr.io/OWNER/IMAGE
```

`GNUPGHOME` is needed because the helper inherits the Docker CLI's
environment and would otherwise look for the keyring under the overridden
`HOME`. The helper resolves its own configuration and `gpgfile` paths from the
password database, so the override does not hide
`~/.config/pinentry.methuselah` or `~/.docker/…`.

To avoid typing the prefix, add a shell function to `~/.bashrc` or
`~/.zshrc`:

```bash
docker() {
  GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/docker-home \
    command docker "$@"
}
```

`command docker` avoids recursion into the function. If you export
`GNUPGHOME` once in your shell startup file, the function only needs to set
`HOME`:

```bash
export GNUPGHOME="$HOME/.gnupg"
docker() {
  HOME=/etc/methuselah/docker-home command docker "$@"
}
```

For scripts, use a wrapper such as `~/.local/bin/docker-methuselah`:

```bash
#!/usr/bin/env bash
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}" HOME=/etc/methuselah/docker-home \
  exec /usr/bin/docker "$@"
```

```bash
chmod +x ~/.local/bin/docker-methuselah
```

Run `docker-methuselah pull …` instead of `docker pull …`. Do not name the
wrapper `docker` unless it calls the real binary by absolute path, or it will
call itself recursively. The wrapper's environment is inherited by the real
Docker CLI, so the helper still sees the same verified caller.

The root-controlled home is intentionally not writable by your account.
Commands that write under `$HOME/.docker`, such as `docker login`,
`docker logout`, `docker context use`, and parts of buildx, will fail. The
helper is read-only, and `docker login` would need its refused `store` action
anyway. Provision any needed context or buildx state as root under the
root-controlled home, or run commands that do not need the helper without the
wrapper.

The helper refuses `--context` and `DOCKER_CONTEXT`. The default context, or a
`currentContext` set by root in the root-controlled config, is what the CLI
uses. Per-user context switching is not supported. `DOCKER_HOST` is refused
too, so a rootless daemon that relies on it needs a root-provisioned context.

### 4. Optional but recommended: pin the CLI binary

While `/etc/methuselah/docker-cli.sha256` exists, the running `docker` image
must match one of its digests. Remove the file only to skip the digest check.
A pin that is present but unusable fails closed: it must be a root-owned
regular file, not writable by group or others, in `sha256sum` form, with at
least one 64-digit hex digest, and at most 64 KiB. `#` comments and blank
lines are allowed. The text after each digest is ignored.

Hash the file the process executes, then keep the pin root-owned:

```bash
sudo install -d -o root -g root -m 0755 /etc/methuselah
sha256sum "$(readlink -f /usr/bin/docker)" |
  sudo tee /etc/methuselah/docker-cli.sha256
sudo chown root:root /etc/methuselah/docker-cli.sha256
sudo chmod 0644 /etc/methuselah/docker-cli.sha256
```

Adjust the path if the CLI is installed under `/usr/local/bin` or
`/opt/methuselah`. Refresh the pin after every Docker CLI update, or the
helper will refuse the new binary.

### 5. Required: restrict ptrace

The caller checks read the Docker CLI's state at one moment. A process of your
own that started the CLI could otherwise attach to it with `ptrace`, rewrite
its arguments or memory, and detach before the helper looks. The helper
therefore refuses to run unless the kernel's Yama `ptrace_scope` is 2 or 3,
which stops a same-user parent from attaching:

```bash
echo 'kernel.yama.ptrace_scope = 2' |
  sudo tee /etc/sysctl.d/99-methuselah-ptrace.conf
sudo sysctl --system
sysctl kernel.yama.ptrace_scope
```

Confirm that the effective value is 2 or 3 before using the helper. Scope 2
also stops same-user debuggers and `strace` from starting or attaching; see
[docs/ptrace.md](ptrace.md) for what that changes. If you cannot or will not
accept it, create a root-owned waiver and accept that malware running as you
can then defeat the caller checks:

```bash
sudo install -d -o root -g root -m 0755 /etc/methuselah
sudo touch /etc/methuselah/allow-weak-ptrace
sudo chown root:root /etc/methuselah/allow-weak-ptrace
```

### 6. Optional: require signed credential files

Anyone who can replace your encrypted file can encrypt credentials of their
own to your public key. Signing closes that gap, because only the holder of
your signing key can produce a valid signature. Sign and encrypt in one step:

```bash
gpg --sign --encrypt --recipient you@example.com \
  --output ~/.docker/ghcr.credentials.gpg credentials.txt
```

Then list the signing key in the root-owned
`/etc/methuselah/docker-signers`, one `<server> <fingerprint>` per line. The
fingerprint is 40 or 64 hex digits without spaces; the primary key or the
signing subkey fingerprint both work. `#` comments and blank lines are
allowed. Print it with `gpg --with-colons --fingerprint you@example.com`:

```bash
sudo install -d -o root -g root -m 0755 /etc/methuselah
echo 'ghcr.io 0123456789ABCDEF0123456789ABCDEF01234567' |
  sudo tee -a /etc/methuselah/docker-signers
sudo chown root:root /etc/methuselah/docker-signers
sudo chmod 0644 /etc/methuselah/docker-signers
```

The server is matched case-sensitively with the same exact, scheme-less,
trailing-slash, host-only, and Docker Hub aliases as the configuration
sections, so `docker.io` covers Docker Hub. A listed server is refused unless
its file carries a good signature from that key and every signature on the
file verifies. A server with no entry, or an absent policy file, enforces
nothing. A policy file that is not root-owned, is malformed, is too large, or
lists overlapping spellings of the same server fails closed.

## What is verified

The helper writes no credentials, and exits non-zero, unless the caller:

- is the native Docker CLI executable at `/opt/methuselah/docker/docker`,
  `/usr/local/bin/docker`, or `/usr/bin/docker`. After symlinks are resolved
  the file name is `docker`. Every path component and the executable are owned
  by root or the `methuselah` service account, never the calling user, and are
  not writable by group or others. The running image is matched by inode
  against `/proc/<pid>/exe`, so a copy, a rename, or a binary replaced on disk
  fails;
- shares the helper's root and mount namespace;
- matches a pinned SHA-256 when `/etc/methuselah/docker-cli.sha256` exists, as
  described above;
- reports no attached tracer when the helper reads the caller's `TracerPid`,
  and runs on a kernel whose Yama `ptrace_scope` is at least 2 (or has the
  root-owned `/etc/methuselah/allow-weak-ptrace` waiver; see step 5);
- was not started with a global option that redirects the daemon, swaps the
  config, or weakens TLS before the subcommand: `--config`, `--context`,
  `--host`, `-c`, `-H`, `--tls`, `--tlsverify`, `--tlscacert`, `--tlscert`,
  `--tlskey`, `--debug`, or `-D`. Options after the subcommand belong to the
  subcommand (or, for `run`, `create`, and `exec`, to the container) and are
  not treated as global. `--log-level` and `-l` are allowed;
- was not started with loader, interpreter, resolver, or trust-store
  overrides: `LD_*`, `MALLOC_*`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
  `HOSTALIASES`, `GODEBUG`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `OPENSSL_*`, or `SSLKEYLOGFILE`.
  The `DOCKER_*` namespace is deny-by-default: only `DOCKER_API_VERSION`,
  `DOCKER_BUILDKIT`, `DOCKER_CLI_EXPERIMENTAL`, `DOCKER_CLI_HINTS`,
  `DOCKER_CONTENT_TRUST`, `DOCKER_DEFAULT_PLATFORM`,
  `DOCKER_HIDE_LEGACY_COMMANDS`, `DOCKER_SCAN_SUGGEST`, and
  `DOCKER_STACK_ORCHESTRATOR` are accepted. In particular, `DOCKER_CONFIG`,
  `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_TLS`, `DOCKER_TLS_VERIFY`,
  `DOCKER_CERT_PATH`, `DOCKER_AUTH_CONFIG`, `DOCKER_CUSTOM_HEADERS`, and
  `DOCKER_CLI_PLUGIN_ORIGINAL_CLI_COMMAND` are refused;
- uses a root-controlled `HOME`, set exactly once and non-empty. `.docker` and
  `.docker/config.json` under it are root-controlled when present;
- maps only executable files owned by root or the `methuselah` account,
  through paths with the same ownership rules, apart from libffi's
  `/memfd:libffi` trampoline. Other deleted mappings are refused. No mapping
  may be a writable and executable file mapping, and none may be anonymous
  and executable (`[vdso]` and `[vsyscall]` are exempt). Anonymous executable
  memory can hold injected code, but some libffi builds also use it for
  closures; if your Docker CLI trips this check (`Docker CLI has … executable
  memory`), accept it with a root-owned waiver:
  `sudo touch /etc/methuselah/allow-anonymous-exec`. A writable and executable
  *file* mapping is always refused;
- writes only to a pipe that the verified caller holds the read end of.

The tracer check is a snapshot; it is the Yama requirement that stops a later
attachment.

The caller is verified before the passphrase prompt. After the prompt the
helper checks that the parent is still that caller, verifies it again, and
writes nothing if a signal arrived in between.

## Threat model

The helper decides which *program* receives your credentials: the genuine,
unmodified Docker CLI that you installed, started in a clean environment with
configuration only root can change, with your encrypted file unaltered (when
signing is on). It is designed to refuse look-alike binaries, redirected
daemons, injected libraries, and replaced files.

It does not stop everything. A process running as you that is allowed to
`ptrace` the CLI can read or rewrite its memory, so the Yama requirement in
step 5 is part of the model, not an extra. With the waiver in place, or with
`CAP_SYS_PTRACE` or root in play, malware running as you can obtain the
credentials. Likewise, a genuine CLI you trust still uses them for whatever
commands you give it.

The Docker daemon is not verified. The helper controls what the CLI receives;
the CLI then sends registry credentials to the registry it was told to use.
The refused `--host`, `--context`, and `DOCKER_*` overrides are what keep that
registry and the CLI configuration fixed.

## Limitations

- Only a native Docker CLI installed by root or the `methuselah` service
  account is accepted. A copy under your own home, a user-installed static
  binary, and Docker Desktop's per-user CLI are refused.
- The helper is read-only: `get` and `list` only. `store` and `erase` are
  refused, so `docker login`, `docker logout`, and any tool that expects to
  save credentials through the helper fail. `list` returns `{}`; it does not
  enumerate encrypted files, because doing so would require decrypting them.
- `HOME` must be root-controlled, so the CLI cannot write its own config.
  `docker login`, context changes, and commands that need a writable
  `~/.docker` do not work under the wrapper. Pulls and pushes that use the
  root-provisioned config do.
- `--context` and `DOCKER_CONTEXT` are refused. Only the default context, or a
  root-provisioned `currentContext`, is available. `DOCKER_HOST` is refused,
  so rootless daemons that depend on it need a root-provisioned context.
- Registry addresses must be printable ASCII without `[`, `]`, `"`, `\`, `#`,
  or `;`, so bracketed IPv6 registry literals are not supported.
- The pin covers the `docker` executable. Ownership and memory-map checks
  cover the rest of the install directory.
- The `methuselah` account can replace its own Docker CLI files. That is the
  trust delegated to the service account. The root-owned pin detects a
  changed executable until the pin is refreshed.
- Arguments and environment are read from `/proc/<pid>/cmdline` and
  `/proc/<pid>/environ`, which reflect the process's current stack memory and
  can be rewritten by a process that is allowed to `ptrace` it. That is why
  `ptrace_scope` matters. Linux only. A caller in another mount namespace, or
  with a different root, cannot be verified.
- A Docker CLI you trust can still use the credentials as the commands you
  give it direct. This helper decides who receives them, not what that CLI
  does.

## Troubleshooting

Build with trace logging (`scripts/debug.sh` or a non-release build) to see
which check refused the caller.

- `no trusted Docker CLI installation found` — the CLI is not at one of the
  three accepted paths, or a path component is owned by your account or
  writable by group or others. Install it as root, or move it to an accepted
  path.
- `caller is not a trusted Docker CLI` — a `docker` at an accepted path is
  trusted, but the running image is a different file. Replace the copy, or
  remove the stale installation.
- `Docker CLI home must be root controlled` — run the CLI with
  `HOME=/etc/methuselah/docker-home`, as shown in step 3.
- `Docker CLI environment variable not allowed` — unset the named variable.
  `DOCKER_HOST`, `DOCKER_CONFIG`, and `DOCKER_CONTEXT` are common causes.
- `Yama ptrace_scope is too low` — set `kernel.yama.ptrace_scope` to 2 or 3,
  or create the waiver described in step 5.
- `no [docker:<server>] gpgfile` — the registry address Docker sent does not
  match a section. Add the exact spelling, the host, or a Docker Hub alias.
- `stdout must be a pipe from the Docker CLI` or `caller is not a trusted
  Docker CLI` when running the helper by hand — expected. The helper only
  answers the Docker CLI, not a shell.
- `Docker CLI does not match its pinned SHA-256` — refresh
  `/etc/methuselah/docker-cli.sha256` after a CLI update.
- `Docker CLI has … executable memory` — if the message is about anonymous
  memory (writable or not), create `/etc/methuselah/allow-anonymous-exec`. A
  writable and executable *file* mapping is never waived.

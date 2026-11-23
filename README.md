```
⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪
⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚫⚪⚪⚫⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚫⚪⚪⚪⚪⚪⚪⚫⚪⚪⚪⚪
⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚫⚪⚪⚫⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚫⚪⚪⚪⚪⚪⚪⚫⚪⚪⚪⚪
⚪⚫⚫⚫⚫⚫⚪⚫⚫⚫⚫⚪⚫⚫⚫⚪⚫⚫⚫⚫⚪⚫⚪⚪⚫⚪⚫⚫⚫⚫⚪⚫⚫⚫⚫⚪⚫⚪⚪⚫⚫⚫⚪⚫⚫⚫⚫⚪
⚪⚫⚪⚫⚪⚫⚪⚫⚪⚪⚫⚪⚪⚫⚪⚪⚫⚪⚪⚫⚪⚫⚪⚪⚫⚪⚫⚪⚪⚪⚪⚫⚪⚪⚫⚪⚫⚪⚪⚪⚪⚫⚪⚫⚪⚪⚫⚪
⚪⚫⚪⚫⚪⚫⚪⚫⚫⚫⚫⚪⚪⚫⚪⚪⚫⚪⚪⚫⚪⚫⚪⚪⚫⚪⚫⚫⚫⚫⚪⚫⚫⚫⚫⚪⚫⚪⚫⚫⚫⚫⚪⚫⚪⚪⚫⚪
⚪⚫⚪⚫⚪⚫⚪⚫⚪⚪⚪⚪⚪⚫⚪⚪⚫⚪⚪⚫⚪⚫⚪⚪⚫⚪⚪⚪⚪⚫⚪⚫⚪⚪⚪⚪⚫⚪⚫⚪⚪⚫⚪⚫⚪⚪⚫⚪
⚪⚫⚪⚫⚪⚫⚪⚫⚫⚫⚫⚪⚪⚫⚫⚪⚫⚪⚪⚫⚪⚫⚫⚫⚫⚪⚫⚫⚫⚫⚪⚫⚫⚫⚫⚪⚫⚪⚫⚫⚫⚫⚪⚫⚪⚪⚫⚪
⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪
```

Credential helper for Git, GPG, SSH

---

![Version](https://img.shields.io/badge/dynamic/regex?url=https%3A%2F%2Fgithub.com%2Frandop%2Fmethuselah%2Fraw%2Frefs%2Fheads%2Fmaster%2FVERSION&search=(.*)&label=Version&color=blue) ![STD: 20](https://img.shields.io/badge/STD-C++20-white)

## Overview

Methuselah is a command-line project focused on credential handling across Git, GPG, and SSH workflows. The project aims to provide a dedicated secure solution for working with credentials in development environments, keeping authentication-related tooling organized and accessible.

## Features

- **Git** — Credential helper integration.
- **GPG** — Support for GPG-related credential workflows.
- **SSH** — Support for SSH-related authentication workflows.
- **AWS CLI** — `credential_process` helper that releases credentials only to
  an untampered, root-owned AWS CLI v2.

---
For additional build options and instructions, see [BUILD.md](BUILD.md).

## AWS CLI

`--macro=aws` is an AWS CLI [`credential_process`](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-sourcing-external.html)
helper. Credentials stay GPG-encrypted at rest and are handed over only after
the calling process has been verified as a genuine AWS CLI v2.

**1. Encrypt the credentials** (type or paste, then press Ctrl-D; nothing goes
through shell history):

```bash
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

**3. Point the CLI at the helper** in `~/.aws/config` (use the absolute path of
a root-owned install) and keep no static keys in `~/.aws/credentials`:

```ini
[profile prod]
credential_process = /usr/local/bin/methuselah --macro=aws prod
```

**4. Optional but recommended: pin the CLI binary.** Pinning detects an
`aws` that was modified in place. Refresh the pin after every AWS CLI upgrade.

```bash
sudo install -d -m 755 /etc/methuselah
sha256sum "$(readlink -f /usr/local/bin/aws)" | sudo tee /etc/methuselah/aws-cli.sha256
```

### What is verified

The helper prints nothing and exits non-zero unless the caller:

- is the native AWS CLI v2 executable at `/usr/local/aws-cli/v2/current/dist/aws`,
  `/usr/local/bin/aws`, or `/usr/bin/aws`, reached through root-owned,
  non-group/other-writable path components, and matched by inode against the
  running process (copies, renamed or replaced binaries fail);
- matches a pinned SHA-256, when `/etc/methuselah/aws-cli.sha256` exists;
- has no tracer attached;
- was not started with `--endpoint-url`, `--ca-bundle`, `--no-verify-ssl`,
  `--debug`, or `configure export-credentials`;
- was not started with `LD_*`, `PYTHON*`, `MALLOC_*`, `AWS_ENDPOINT_URL*`,
  `AWS_CA_BUNDLE`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, or common
  CA-bundle (`SSL_CERT_*`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`) variables;
- maps only root-owned files as executable code.

The check runs before the passphrase prompt and again just before the
credentials are written.

### Limitations

- AWS CLI v1 (a Python script, e.g. Debian's `awscli`) and user-owned installs
  such as `~/.local/aws-cli` are rejected on purpose: the files they run can be
  changed by any process of your user. Install v2 system-wide as root.
- The pin covers the `aws` launcher, not every file in its install directory;
  the root-ownership and memory-map checks cover those.
- Environment and arguments are what the CLI was started with, which is what
  the kernel reports in `/proc`. Linux only.
- An AWS CLI you trust can still use the credentials as the commands you give
  it direct. This helper decides who receives them, not what that CLI does.

## Security

Credentials and authentication keys are sensitive.

- Never commit private keys, passwords, tokens, or other secrets.
- Keep private SSH and GPG key material protected.
- Avoid exposing credentials through command-line arguments, shell history, or logs.
- Follow appropriate file permission and access-control practices.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

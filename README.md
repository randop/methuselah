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

Credential helper for Git, GPG, SSH, AWS CLI, and Docker

---

![Version](https://img.shields.io/badge/dynamic/regex?url=https%3A%2F%2Fgithub.com%2Frandop%2Fmethuselah%2Fraw%2Frefs%2Fheads%2Fmaster%2FVERSION&search=(.*)&label=Version&color=blue) ![STD: 20](https://img.shields.io/badge/STD-C++20-white)

## Overview

Methuselah is a command-line project focused on credential handling across Git, GPG, SSH, AWS CLI, and Docker workflows. The project aims to provide a dedicated secure solution for working with credentials in development environments, keeping authentication-related tooling organized and accessible.

## Features

- **Git** — Credential helper integration.
- **GPG** — Support for GPG-related credential workflows.
- **SSH** — Support for SSH-related authentication workflows.
- **AWS CLI** — `credential_process` helper that releases credentials only to
  an untampered AWS CLI v2 owned by root or the dedicated `methuselah` service
  account.
- **Docker** — Read-only credential helper for the Docker CLI. Credentials
  stay GPG-encrypted and are released only to a verified, root-managed Docker
  CLI.

---
For additional build options and instructions, see [BUILD.md](BUILD.md).
For AWS CLI setup and verification details, see [docs/aws.md](docs/aws.md).
For Docker credential helper setup and verification details, see
[docs/docker.md](docs/docker.md).

## Security

Credentials and authentication keys are sensitive.

- Never commit private keys, passwords, tokens, or other secrets.
- Keep private SSH and GPG key material protected.
- Avoid exposing credentials through command-line arguments, shell history, or logs.
- Follow appropriate file permission and access-control practices.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

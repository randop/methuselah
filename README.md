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

---
For additional build options and instructions, see [BUILD.md](BUILD.md).

## Security

Credentials and authentication keys are sensitive.

- Never commit private keys, passwords, tokens, or other secrets.
- Keep private SSH and GPG key material protected.
- Avoid exposing credentials through command-line arguments, shell history, or logs.
- Follow appropriate file permission and access-control practices.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

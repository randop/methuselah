# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-11-23

### Added
- `--macro=aws`: an AWS CLI `credential_process` helper. Credentials stay in a
  GPG-encrypted file (`[aws:<profile>]` section in
  `~/.config/pinentry.methuselah`) and are released only to a verified AWS
  CLI v2, as the JSON document the CLI expects, written straight to its pipe.
- `AwsCliVerifier`: refuses to hand over credentials unless the calling
  process is the native `aws` binary owned by root or the `methuselah` service
  account (matched by the inode of `/proc/<pid>/exe`, so a swapped, copied, or
  deleted binary fails), is not traced, and has no tampering vectors:
  - optional SHA-256 pin of the running binary in
    `/etc/methuselah/aws-cli.sha256` (root-owned);
  - no `LD_*`, `PYTHON*`, `MALLOC_*`, endpoint, or CA-bundle overrides in its
    start-up environment;
  - none of `--endpoint-url`, `--ca-bundle`, `--no-verify-ssl`, `--debug`, or
    `configure export-credentials` in its arguments;
  - every executable file mapping is owned by root or the service account (no
    `/tmp` libraries, deleted files, or memfd code, apart from libffi's
    trampoline memfd).
- `scripts/aws.sh` installs AWS CLI v2 under `/opt/methuselah/aws-cli` for the
  unprivileged `methuselah` system user, with read and execute access for the
  `users` group, a root-owned launcher symlink, and a refreshed SHA-256 pin.
- `Security::trusted_file()` (the `trusted_executable()` rules without the
  executable bit) and `ProcessInfo::readProc()` / `ProcessInfo::argv()`.
- `InstanceLock::Mode::wait`: concurrent `credential_process` calls queue
  behind each other instead of exiting.
- Unit tests (`meson test -C .build`) for the credential parser, the verifier
  checks, and `verify()` against real child processes.

### Changed
- `AwsCliVerifier` accepts an AWS CLI v2 installed under
  `/opt/methuselah/aws-cli` and owned by the unprivileged `methuselah` service
  account in addition to root-owned installations. Path components may belong
  to root or `methuselah`, but never to the calling user, and must not be
  writable by group or others.
- The unknown-macro check now runs before the instance lock is taken.
- `Security::verify_git()`, `verify_gpg()`, `verify_ssh()`, and `verify_aws()`
  return a `SecurityVerdict` (`std::errc` result plus a reason). Success uses
  `std::errc{}`, policy refusals use `std::errc::permission_denied`, and
  verification faults use `std::errc::io_error`. The verdict can be unpacked
  with `const auto [result, reason] = ...`. `reason` is a `std::string_view`
  that only accepts string literals, so it cannot dangle; variable detail
  (an argument, variable, or path) moved to trace logging.
  `AwsVerdict` and the `verify_aws(std::string *)` out-parameter are gone.

### Security
- The AWS macro re-verifies the caller after the passphrase prompt, right
  before writing credentials, and refuses a stdout that is not a pipe.
- The encrypted credentials file must be a regular file owned by the user and
  not writable by group or others.
- Expired credentials, unknown keys, duplicate keys, and values outside the
  characters AWS uses are rejected; errors never include secret values.
- A failed, cancelled, or contended AWS request exits non-zero with no output;
  it never reports an empty success.

## [0.7.1] - 2026-11-23

### Security
- Fixed CVE-2026-129975, a double free in GPGME's `read_status()` and
  `read_colon_line()` reachable through a crafted OpenPGP key with a very long
  user ID. Both functions grew their 1024-byte buffer but only wrote the new
  pointer back to the engine context on exit, so early returns left a stale
  pointer that was later freed a second time. The flaw dates back to 2002 and
  could allow data exfiltration and possibly remote code execution.

### Changed
- Raised the minimum GPGME version from 2.2.0 to 2.3.1 in `meson.build`, and
  `scripts/deps.sh` now builds gpgme 2.3.1.
- `scripts/deps.sh` rebuilds gpgme when its pkg-config metadata is missing or
  older than the pinned version, so an existing 2.2.0 build is replaced.

## [0.7.0] - 2026-11-21

### Added
- `tests/security.sh`, a Linux-only script that launches the helper and checks
  its process hardening, with an optional check that startup is refused under
  `strace`.
- `scripts/deps-x11.sh` builds the X11 libraries and OpenGL dispatch under
  `$HOME/opt/x11`.
- `scripts/tests.sh`, an end-to-end test that reloads the GPG agent and runs a
  `gpg --clearsign` passphrase prompt through the pinentry.
- Local `fmt` 12.0.0 wrap in `subprojects/` so spdlog's `fmt` dependency does
  not rely on WrapDB.

### Changed
- libsodium 1.0.22 or newer, built as a static library, is now a required
  dependency. `scripts/deps.sh` builds it when the distribution does not supply
  it, and `BUILD.md` documents the requirement.
- `scripts/compile.sh` and `scripts/debug.sh` add the X11 prefix to
  `PKG_CONFIG_PATH` and `CMAKE_PREFIX_PATH`, and reconfigure Meson when
  `build.ninja` is missing instead of only checking for the build directory.
  `scripts/compile.sh` also warns when X11 has not been built.

### Fixed
- Build detects whether the compiler supports C++23 `std::format` and disables
  spdlog's `std_format` option when it does not (for example on GCC 12).
- `scripts/deps.sh` puts the locally built libgpg-error first in `PATH`, so
  gpgme's configure step no longer picks up the system libgpg-error 1.46 when
  it needs 1.47 or newer.

### Security
- Added libsodium guarded memory for secrets via `SecureString` and
  `SecureArray`, with a canary, best effort `MADV_DONTDUMP`, and zeroing on free.
  `sodium_malloc()` locks memory on a best effort basis and can return
  swappable memory if the locked memory limit is exhausted. Both wrappers
  verify locking before use and fail the allocation if locking fails.
- Added `MemoryGuard::harden()` at startup. Disabling dumpability and core
  files and setting `no_new_privs` are best effort: each failure emits a
  warning and startup continues. Startup refuses a detected tracer
  (`TracerPid`) and removes selected `LD_*` and malloc debug variables.
- `secure_clear()` now uses `sodium_memzero()`.
- Git credential input is parsed with `string_view`s into a guarded `SecureString`
  (no `istringstream`/map/`substr` copies); passwords are written via `write(2)`
  instead of `std::cout`, and the ssh macro does the same.
- Short secrets are forced onto the guarded heap (`secure_reserve`) so they
  never sit in the inline small-string buffer.

## [0.6.2] - 2026-11-09

### Added
- Security verification for the GPG macro, checking that the calling process is
  `gpg-agent`, `gpg`, or `gpg2`.

### Security
- GPG pinentry requests are rejected unless the caller is a root-owned GPG
  executable without group/other write access.

## [0.6.1] - 2026-11-09

### Added
- Security verification for the Git and SSH macros, checking that the calling
  process is the expected executable.
- Support for `ssh-add` as an SSH macro caller.

### Changed
- Trusted executable validation now lives in the `Security` class; the
  standalone `trusted_executable.hpp` header was removed.

### Security
- Git and SSH helpers accept only root-owned executables without group/other
  write access.

## [0.6.0] - 2026-11-03

### Added
- Blurred `*` mask for the passphrase field, sized to the typed text and drawn
  with a soft halo so the plaintext stays hidden.

### Changed
- Passphrase prompt now uses a dedicated layout instead of
  `GuiTextInputBox()`, keeping the reveal toggle and Continue/Cancel actions.
- `scripts/compile.sh` configures Meson with `--prefer-static` and
  `--default-library=static`.
- `scripts/deps.sh` builds libassuan with `--disable-doc`.

### Fixed
- Caret remains visible while editing, including when long passphrases scroll
  horizontally.

### Security
- Plaintext passphrase characters are no longer rendered while the masking
  overlay is active.

## [0.5.3] - 2026-11-02

### Added
- `scripts/deps.sh` builds static libgpg-error 1.61, libassuan 3.0.2, and
  gpgme 2.2.0 under `$HOME/opt`.
- `BUILD.md` containing the dependency and build instructions moved out of
  the README.
- Version and C++20 badges to the README.

### Changed
- README now focuses on the project overview, features, security guidance, and
  license.
- `scripts/deps.sh` pins the GPG stack versions and reports the resulting
  pkg-config paths and static library locations.

### Fixed
- SSH askpass wrapper automatically answers new host-key confirmation prompts
  and delegates all other prompts to Methuselah.

## [0.5.2] - 2026-10-28

### Changed
- Git credential mode handles only `git credential get`; `store` and `erase`
  exit without prompting.
- Git credential fields are parsed into a map instead of Boost.PropertyTree.
- `scripts/format.sh` now requires Meson 1.5 or newer and fails with a clear
  error.
- GPG and SSH wrappers `exec` the helper so signals and exit codes propagate.
- `scripts/debug.sh` configures and compiles the debug build before running
  GDB.
- Documented the full Debian build dependencies and Boost 1.90.0 installation.

### Fixed
- `--version` no longer reads past `argv` when no arguments are given.
- Pinentry `CONFIRM` requests report `GPG_ERR_NOT_CONFIRMED` instead of
  always succeeding.
- raygui dependency is supplied via the wrap's `patch_directory`, fixing the
  Meson subproject setup.

### Security
- Instance lock is created in `$XDG_RUNTIME_DIR` (falling back to a per-UID
  file in `/tmp`) with `0600`, `O_NOFOLLOW`, and `O_CLOEXEC`.
- Lock file is no longer unlinked on release, preventing pre-creation attacks.

## [0.5.1] - 2026-08-28

### Added
- SSH agent passphrase mode via `--macro=ssh`.
- `scripts/methuselah-ssh-wrapper` helper script.

### Security
- SSH passphrases are cleared from memory after being written to stdout.

## [0.4.1] - 2026-08-26

### Added
- Signed-distance-field (SDF) shader for high-quality text rendering.
- `--macro=dummy` mode for inspecting the UI.

### Changed
- Added high-DPI window support and scaled the UI for HiDPI displays.
- Expanded the embedded font atlas to cover characters 32 through 255.
- Added a debug log callback for UI diagnostics.

## [0.4.0] - 2026-08-21

### Added
- `--version` command-line option.
- Dedicated modules for application flow, configuration, git credentials, GPG
  decryption, instance locking, logging, path handling, pinentry serving,
  signal handling, UI sessions, and secure memory.

### Changed
- Refactored the monolithic `main.cpp` into focused modules.
- Replaced manual cleanup with RAII wrappers around GPGME and Assuan resources.
- Updated the README to describe the project as a GPG and Git credential helper,
  with the full Arch/Artix build toolchain.

### Security
- Centralized secure clearing of passphrases and decrypted secrets.

## [0.3.2] - 2026-08-21

### Changed
- Merged pinentry dialog state into the application state.
- Dialog title and prompt now come from the active application macro.
- Declared Meson `>= 1.0.1` as the minimum build version.

### Fixed
- Pinentry accept loop now stops when a signal is received.

## [0.3.1] - 2026-08-21

### Added
- `VERSION` file as the single source of the project version.

### Changed
- Removed the deprecated `debug.hpp` logging macros.
- Release builds now enable `-O3`, LTO, stripping, and `NDEBUG`.

## [0.3.0] - 2026-08-20

### Added
- `gpg-error` and `libassuan` library dependencies.
- GPG agent `pinentry-program` wrapper script.
- Assuan pinentry server supporting `SETDESC`, `SETPROMPT`, `SETTITLE`,
  `SETERROR`, `SETTIMEOUT`, `SETREPEAT`, `GETPIN`, and `CONFIRM`.
- Passphrase dialog with timeout, masked input, and secure passphrase handoff.

### Changed
- Release is now the default build type.

### Fixed
- Unknown macros now exit with a failure status.

### Security
- Pinentry passphrases are sent over a confidential Assuan channel and cleared
  from memory after use.

## [0.2.1] - 2026-08-19

### Added
- spdlog-based logging with build-type-specific log levels.

### Changed
- Routed raylib logs through spdlog.
- Normalized process exit codes to `EXIT_SUCCESS` and `EXIT_FAILURE`.

## [0.2.0] - 2026-08-07

### Added
- `--macro=git` and `--macro=gpg` entry points.
- Shared pinentry configuration at `~/.config/pinentry.methuselah`.

### Changed
- Renamed the project description from "git credential helper" to
  "pinentry helper".
- Added Artix/Arch dependency installation instructions.
- Moved the project to the top-level `methuselah/` directory.

### Fixed
- Corrected Boost detection during build setup.

## [0.1.3] - 2026-06-11

### Added
- Git credential protocol parsing and credential handoff.
- Boost-backed INI configuration mapping hosts to GPG files.
- Debug logging macros for development builds.

### Changed
- Lowered the C++ standard to C++20 for older Debian systems.
- Added automatic raygui bootstrap and pinned gpgme 1.23.2 in the build scripts.
- Added automated Boost download and build to the dependency setup.
- Ignored `git credential store` invocations.

### Fixed
- Build issues with Boost, raygui, and gpgme on older distributions.

## [0.1.2] - 2026-05-29

### Added
- GPG decryption through gpgme with a passphrase callback.
- Passphrase-driven git credential unlocking flow.
- Dependency setup script for gpgme.
- `~` and `$HOME` path expansion and canonicalization.

### Security
- Passphrase buffers are explicitly cleared with `explicit_bzero` after use.

## [0.1.1] - 2026-05-29

### Added
- Embedded Hack font and high-quality text rendering with MSAA, mipmaps, and
  trilinear filtering.
- Passphrase input box with Continue/Cancel actions and a secret input toggle.
- Timestamped raylib log callback.

### Fixed
- Corrected GUI component dimensions and layout.

## [0.1.0] - 2026-05-28

### Added
- Initial raylib/raygui fullscreen git credential helper.
- Single-instance lock that focuses an existing window.
- Signal handling and cleanup.

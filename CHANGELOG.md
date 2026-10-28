# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Reformatted `meson.build` and added `meson format` to `scripts/format.sh`.

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

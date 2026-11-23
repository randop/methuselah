#pragma once

#include "methuselah/security.hpp"

#include <sys/types.h>

#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace methuselah {

// Decides whether the process that invoked `credential_process` is a genuine,
// untampered AWS CLI v2. Every check fails closed: anything that cannot be
// inspected is reported with `std::errc::io_error`, never as success.
//
//  1. The running image (/proc/<pid>/exe, by inode, so a path swapped after
//     exec cannot fool it) is an `aws` reached through a chain of components
//     owned by root or the `methuselah` service account, none of them writable
//     by group or others.
//  2. Optionally, its SHA-256 matches a root-owned pin list.
//  3. No tracer is attached (no ptrace injection).
//  4. Its argv does not redirect, weaken, or dump what it does with
//     credentials (--endpoint-url, --no-verify-ssl, --debug,
//     `configure export-credentials`, ...).
//  5. Its start-up environment carries no user-controlled loader, interpreter,
//     endpoint, or trust-store overrides.
//  6. Its CLI configuration files are root controlled, with no plugins
//     or auto-prompt activation.
//  7. Every executable file mapping is trusted, except libffi trampolines.
class AwsCliVerifier {
public:
  struct Options {
    // Install locations of the native AWS CLI v2 executable.
    std::vector<std::filesystem::path> candidates;
    // File name every resolved candidate must have (guards against an `aws`
    // symlink that resolves to an interpreter or shell).
    std::string required_name = "aws";
    // Optional root-owned list of allowed SHA-256 digests (sha256sum format).
    // Absent file: pinning is skipped. Present but unusable: verification
    // faults.
    std::filesystem::path pin_file;
    // UIDs allowed to own the CLI installation. Root is always accepted;
    // default_options() adds the unprivileged `methuselah` service account
    // when it exists. The calling user is never added.
    std::vector<uid_t> install_owners{0};
  };

  [[nodiscard]] static Options default_options();

  AwsCliVerifier() : options_(default_options()) {}
  explicit AwsCliVerifier(Options options) : options_(std::move(options)) {}

  [[nodiscard]] SecurityVerdict verify(pid_t pid) const;

  // Pure helpers, exposed for unit tests.

  // `environment` is the raw NUL-separated /proc/<pid>/environ. Returns the
  // offending variable name. Pass the official bundle's trusted directory
  // to allow its exact library path.
  [[nodiscard]] static std::optional<std::string>
  forbidden_environment(std::string_view environment,
                        std::string_view bundle_library_path = {});

  // Scans a trusted AWS config or credentials file for auto-prompt; only
  // the config file can supply plugins.
  [[nodiscard]] static SecurityVerdict scan_cli_config(std::istream &stream,
                                                       bool check_plugins);

  // Returns the offending argument.
  [[nodiscard]] static std::optional<std::string>
  forbidden_arguments(const std::vector<std::string> &args);

  // Paths of file-backed, executable mappings from /proc/<pid>/maps. A
  // trailing " (deleted)" is preserved so callers can reject it.
  [[nodiscard]] static std::vector<std::string>
  executable_mapping_paths(std::string_view maps);

  // Parses sha256sum-style lines ("<64 hex>  <name>"), '#' comments and blank
  // lines allowed. Digests are returned lowercase. Any malformed line makes
  // the whole list invalid (nullopt), as does an empty list.
  [[nodiscard]] static std::optional<std::vector<std::string>>
  parse_pin_file(std::string_view text);

  // Lowercase hex SHA-256 of everything readable from `fd`.
  [[nodiscard]] static std::optional<std::string> sha256_hex(int fd);

private:
  Options options_;
};

} // namespace methuselah
